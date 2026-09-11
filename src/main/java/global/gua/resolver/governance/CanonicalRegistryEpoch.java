package global.gua.resolver.governance;

import global.gua.resolver.crypto.CanonicalEncoder;

/**
 * The {@code gua-registry-epoch.v1} canonical bytes, encoded with {@code gua-lp.v1} (ADM-007). One object
 * shape serves all four registries; the {@code registry} field is what separates their chains.
 *
 * <p>Field order: schema tag; registry (canonical name); genesisId; epoch (int64); previousEpochHash (empty
 * at epoch 1); issuedAt (int64 epoch ms); contentHash. Signatures are outside these bytes.
 */
public final class CanonicalRegistryEpoch {

    private CanonicalRegistryEpoch() {}

    public static byte[] bytes(RegistryEpoch epoch) {
        if (epoch == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("epoch is required");
        }
        if (epoch.registry() == null || epoch.issuedAt() == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("registry and issuedAt are required");
        }
        return CanonicalEncoder.begin(RegistryEpoch.SCHEMA)
                .string(epoch.registry().wireName())
                .string(epoch.genesisId())
                .int64(epoch.epoch())
                .string(epoch.previousEpochHash())
                .int64(epoch.issuedAt().toEpochMilli())
                .string(epoch.contentHash())
                .toByteArray();
    }

    /** The epoch hash: the next epoch's {@code previousEpochHash} and the MEMBERSHIP_EPOCH leaf payload. */
    public static String hash(RegistryEpoch epoch) {
        return CanonicalEncoder.sha256Hex(bytes(epoch));
    }
}
