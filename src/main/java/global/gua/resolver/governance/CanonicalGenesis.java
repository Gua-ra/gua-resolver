package global.gua.resolver.governance;

import java.util.List;

import global.gua.resolver.crypto.CanonicalEncoder;

/**
 * The {@code gua-federation-genesis.v1} canonical bytes, encoded with {@code gua-lp.v1} (ADM-007).
 *
 * <p>Field order: schema tag; federationLabel; createdAt (int64 epoch ms); hashSuite; threshold (int64);
 * keys as a list sorted by keyId, each {keyId, alg, publicKey, operatorId}; registries as a set.
 * Signatures are outside these bytes.
 */
public final class CanonicalGenesis {

    private CanonicalGenesis() {}

    public static byte[] bytes(FederationGenesis genesis) {
        if (genesis == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("genesis is required");
        }
        if (genesis.createdAt() == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("createdAt is required");
        }
        List<GovernanceKey> keys =
                CanonicalOrder.sortedUnique(genesis.keys(), GovernanceKey::keyId, "governance key id");
        CanonicalEncoder e = CanonicalEncoder.begin(FederationGenesis.SCHEMA)
                .string(genesis.federationLabel())
                .int64(genesis.createdAt().toEpochMilli())
                .string(genesis.hashSuite())
                .int64(genesis.threshold())
                .listCount(keys.size());
        for (GovernanceKey key : keys) {
            e.string(key.keyId()).string(key.alg()).string(key.publicKey()).string(key.operatorId());
        }
        return e.stringSet(genesis.registries()).toByteArray();
    }

    /** {@code genesisId}: SHA-256 of the canonical bytes, lowercase hex. The federation's real identity. */
    public static String id(FederationGenesis genesis) {
        return CanonicalEncoder.sha256Hex(bytes(genesis));
    }

    /**
     * The human fingerprint: the first 16 hex characters of the genesis id, grouped in fours. It is what an
     * operator reads aloud or compares between independent channels, so it is short enough to check by eye
     * and long enough that producing a second genesis with the same one is not a thing anyone can do
     * casually. The full id is what code compares.
     */
    public static String fingerprint(String genesisId) {
        if (genesisId == null || genesisId.length() < 16) {
            throw new GovernanceException("a genesis id is 64 hex characters");
        }
        String head = genesisId.substring(0, 16);
        return String.join(" ", head.substring(0, 4), head.substring(4, 8),
                head.substring(8, 12), head.substring(12, 16));
    }
}
