package global.gua.resolver.governance;

import global.gua.resolver.crypto.CanonicalEncoder;

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

    public static String hash(RegistryEpoch epoch) {
        return CanonicalEncoder.sha256Hex(bytes(epoch));
    }
}
