/*
 * Copyright 2026 Gua
 */
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

/** One leaf per changed root, never per record: every log leaf reseeds new-account fallback placement. */
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

    public static byte[] canonicalBytes(PlacementCheckpoint cp) {
        return ("gua-placement-checkpoint.v1\nroot=" + cp.merkleRoot() + "\nsize=" + cp.size()
                + "\nissuedAt=" + cp.issuedAt().toEpochMilli() + "\n").getBytes(StandardCharsets.UTF_8);
    }

    @Scheduled(fixedDelayString = "${gua.resolver.placement.checkpoint-interval:PT1H}")
    public synchronized PlacementCheckpoint.Signed publish() {
        PlacementCheckpoint cp = records.checkpoint();
        List<SignedRoster.AuthoritySignature> signatures = signingKey == null || keyId == null
                ? List.of()
                : List.of(new SignedRoster.AuthoritySignature(keyId,
                        Ed25519.sign(signingKey, canonicalBytes(cp))));
        PlacementCheckpoint.Signed signed = new PlacementCheckpoint.Signed(cp, signatures);
        if (cp.size() > 0 && !transparencyLog.hasLeaf(EVENT_TYPE, cp.merkleRoot())) {
            transparencyLog.append(EVENT_TYPE, null, cp.merkleRoot());
            log.info("Published placement checkpoint root={} size={}", cp.merkleRoot(), cp.size());
        }
        cached = signed;
        return signed;
    }

    public PlacementCheckpoint.Signed current() {
        PlacementCheckpoint.Signed c = cached;
        return c != null ? c : publish();
    }
}
