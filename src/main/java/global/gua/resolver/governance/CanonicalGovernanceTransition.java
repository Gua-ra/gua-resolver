package global.gua.resolver.governance;

import java.util.List;

import global.gua.resolver.crypto.CanonicalEncoder;

/**
 * The {@code gua-governance-transition.v1} canonical bytes, encoded with {@code gua-lp.v1} (ADM-007).
 *
 * <p>Field order: schema tag; genesisId; index (int64); previousHash; issuedAt (int64 epoch ms);
 * newThreshold (int64); newKeys as a list sorted by keyId, each {keyId, alg, publicKey, operatorId}.
 * Signatures are outside these bytes, because a transition carries two sets of them.
 */
public final class CanonicalGovernanceTransition {

    private CanonicalGovernanceTransition() {}

    public static byte[] bytes(GovernanceTransition transition) {
        if (transition == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("transition is required");
        }
        if (transition.issuedAt() == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("issuedAt is required");
        }
        List<GovernanceKey> keys = CanonicalOrder.sortedUnique(transition.newKeys(), GovernanceKey::keyId,
                "governance key id");
        CanonicalEncoder e = CanonicalEncoder.begin(GovernanceTransition.SCHEMA)
                .string(transition.genesisId())
                .int64(transition.index())
                .string(transition.previousHash())
                .int64(transition.issuedAt().toEpochMilli())
                .int64(transition.newThreshold())
                .listCount(keys.size());
        for (GovernanceKey key : keys) {
            e.string(key.keyId()).string(key.alg()).string(key.publicKey()).string(key.operatorId());
        }
        return e.toByteArray();
    }

    /** The hash the next transition in the chain names as its {@code previousHash}. */
    public static String hash(GovernanceTransition transition) {
        return CanonicalEncoder.sha256Hex(bytes(transition));
    }
}
