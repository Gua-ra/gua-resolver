package global.gua.resolver.placement.record;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.SignedRoster;

/**
 * Anchors the placement state in the transparency log, mirroring the directory checkpoint service.
 *
 * <p>One leaf per record is exactly what this must not do. The roster version is the log size, and
 * {@code WeightedFallbackRule} seeds on the roster version, so every appended leaf moves new-account
 * fallback placement (ADM-001 L6 [CODE]). A per-record leaf would churn placement on every ingest. Instead
 * this computes the Merkle root over the records once per interval and appends a {@code PLACEMENT_CHECKPOINT}
 * leaf only when that root has actually changed, which bounds the churn to one leaf per interval in which
 * the placement state moved.
 *
 * <p>The signed root is an assertion by this node, not a proof that the state is correct, and no per-record
 * inclusion proof is served (ADM-001 L11). Authority mode only, and only with the placement flag on.
 */
@Component
@ConditionalOnExpression(PlacementFeature.ENABLED)
public class PlacementCheckpointService {

    public static final String EVENT_TYPE = "PLACEMENT_CHECKPOINT";

    private static final Logger log = LoggerFactory.getLogger(PlacementCheckpointService.class);

    private final JdbcPlacementRecordStore records;
    private final JdbcTransparencyLog transparencyLog;
    private final String keyId;
    private final PrivateKey signingKey;

    private volatile PlacementCheckpoint.Signed cached;

    public PlacementCheckpointService(JdbcPlacementRecordStore records,
                                      JdbcTransparencyLog transparencyLog, ResolverProperties props) {
        this.records = records;
        this.transparencyLog = transparencyLog;
        ResolverProperties.Authority auth = props.getAuthority();
        this.keyId = auth.getSigningKeyId();
        this.signingKey = (auth.getSigningPrivateKey() == null || auth.getSigningPrivateKey().isBlank())
                ? null : Ed25519.privateKey(auth.getSigningPrivateKey());
    }

    /** Canonical bytes signed over a placement checkpoint. */
    public static byte[] canonicalBytes(PlacementCheckpoint cp) {
        return ("gua-placement-checkpoint.v1\nroot=" + cp.merkleRoot() + "\nsize=" + cp.size()
                + "\nissuedAt=" + cp.issuedAt().toEpochMilli() + "\n").getBytes(StandardCharsets.UTF_8);
    }

    /** Build, sign, and (only if the root is new) log the current placement checkpoint. */
    @Scheduled(fixedDelayString = "${gua.resolver.placement.checkpoint-interval:PT1H}")
    public synchronized PlacementCheckpoint.Signed publish() {
        PlacementCheckpoint cp = records.checkpoint();
        List<SignedRoster.AuthoritySignature> signatures = signingKey == null || keyId == null
                ? List.of()
                : List.of(new SignedRoster.AuthoritySignature(keyId,
                        Ed25519.sign(signingKey, canonicalBytes(cp))));
        PlacementCheckpoint.Signed signed = new PlacementCheckpoint.Signed(cp, signatures);
        // An empty placement state carries no commitment, and anchoring it would bump the log size, and with
        // it every new-account fallback decision, for nothing. Idempotent per root once there are records.
        if (cp.size() > 0 && !transparencyLog.hasLeaf(EVENT_TYPE, cp.merkleRoot())) {
            transparencyLog.append(EVENT_TYPE, null, cp.merkleRoot());
            log.info("Published placement checkpoint root={} size={}", cp.merkleRoot(), cp.size());
        }
        cached = signed;
        return signed;
    }

    /** The current signed checkpoint, computing one on first access. */
    public PlacementCheckpoint.Signed current() {
        PlacementCheckpoint.Signed c = cached;
        return c != null ? c : publish();
    }
}
