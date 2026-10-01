package global.gua.resolver.governance;

import java.util.List;

import global.gua.resolver.crypto.CanonicalEncoder;

/** Registries are encoded as a sorted set, so their JSON order never changes the genesisId. */
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

    public static String id(FederationGenesis genesis) {
        return CanonicalEncoder.sha256Hex(bytes(genesis));
    }

    public static String fingerprint(String genesisId) {
        if (genesisId == null || genesisId.length() < 16) {
            throw new GovernanceException("a genesis id is 64 hex characters");
        }
        String head = genesisId.substring(0, 16);
        return String.join(" ", head.substring(0, 4), head.substring(4, 8),
                head.substring(8, 12), head.substring(12, 16));
    }
}
