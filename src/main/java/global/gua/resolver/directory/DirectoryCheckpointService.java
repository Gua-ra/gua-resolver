package global.gua.resolver.directory;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.SignedRoster;

/**
 * Authority-side directory checkpoint publisher: periodically computes the directory Merkle root, signs it
 * with the authority key, and appends the root to the transparency log ({@code DIRECTORY_CHECKPOINT},
 * idempotent per root) so existing-account routing is committed, auditable, and non-equivocable. Mirrors and
 * clients read the signed checkpoint from {@code /directory/checkpoint}. Authority mode only.
 */
@Component
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class DirectoryCheckpointService {

    public static final String EVENT_TYPE = "DIRECTORY_CHECKPOINT";

    private static final Logger log = LoggerFactory.getLogger(DirectoryCheckpointService.class);

    private final JdbcDirectoryStore directory;
    private final JdbcTransparencyLog transparencyLog;
    private final String keyId;
    private final PrivateKey signingKey;

    private volatile DirectoryCheckpoint.Signed cached;

    public DirectoryCheckpointService(JdbcDirectoryStore directory, JdbcTransparencyLog transparencyLog,
                                      ResolverProperties props) {
        this.directory = directory;
        this.transparencyLog = transparencyLog;
        ResolverProperties.Authority auth = props.getAuthority();
        this.keyId = auth.getSigningKeyId();
        this.signingKey = (auth.getSigningPrivateKey() == null || auth.getSigningPrivateKey().isBlank())
                ? null : Ed25519.privateKey(auth.getSigningPrivateKey());
    }

    /** Canonical bytes signed over a directory checkpoint. */
    public static byte[] canonicalBytes(DirectoryCheckpoint cp) {
        return ("gua-directory-checkpoint.v1\nroot=" + cp.merkleRoot() + "\nsize=" + cp.size()
                + "\nissuedAt=" + cp.issuedAt().toEpochMilli() + "\n").getBytes(StandardCharsets.UTF_8);
    }

    /** Build, sign, and (if the root is new) log the current directory checkpoint. */
    @Scheduled(fixedDelayString = "${gua.resolver.directory.checkpoint-interval:PT5M}")
    public synchronized DirectoryCheckpoint.Signed publish() {
        DirectoryCheckpoint cp = directory.checkpoint();
        List<SignedRoster.AuthoritySignature> sigs = signingKey == null || keyId == null
                ? List.of()
                : List.of(new SignedRoster.AuthoritySignature(keyId,
                        Ed25519.sign(signingKey, canonicalBytes(cp))));
        DirectoryCheckpoint.Signed signed = new DirectoryCheckpoint.Signed(cp, sigs);
        // Only anchor a non-empty directory (an empty checkpoint carries no commitment and would otherwise
        // bump the roster/log version at startup for nothing). Idempotent per root once there are entries.
        if (cp.size() > 0 && !transparencyLog.hasLeaf(EVENT_TYPE, cp.merkleRoot())) {
            transparencyLog.append(EVENT_TYPE, "directory:size" + cp.size(), cp.merkleRoot());
            log.info("Published directory checkpoint root={} size={}", cp.merkleRoot(), cp.size());
        }
        cached = signed;
        return signed;
    }

    /** The current signed checkpoint, computing one on first access. */
    public DirectoryCheckpoint.Signed current() {
        DirectoryCheckpoint.Signed c = cached;
        return c != null ? c : publish();
    }
}
