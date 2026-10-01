package global.gua.resolver.governance;

import java.util.List;

import global.gua.resolver.crypto.CanonicalEncoder;

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

    public static String hash(GovernanceTransition transition) {
        return CanonicalEncoder.sha256Hex(bytes(transition));
    }
}
