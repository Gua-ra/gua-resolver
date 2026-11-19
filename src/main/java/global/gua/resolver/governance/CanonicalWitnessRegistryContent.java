package global.gua.resolver.governance;

import java.util.List;

import global.gua.resolver.crypto.CanonicalEncoder;

/**
 * The {@code gua-witness-registry-content.v1} canonical bytes: schema tag; requiredWitnesses (int64); keys as a
 * list sorted by keyId, each {keyId, alg, publicKey, operatorId, role, url (optional)}.
 */
public final class CanonicalWitnessRegistryContent {

    private CanonicalWitnessRegistryContent() {}

    public static byte[] bytes(WitnessRegistryContent content) {
        if (content == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("witness list is required");
        }
        List<CheckpointKey> keys =
                CanonicalOrder.sortedUnique(content.keys(), CheckpointKey::keyId, "checkpoint key id");
        CanonicalEncoder e = CanonicalEncoder.begin(WitnessRegistryContent.SCHEMA)
                .int64(content.requiredWitnesses())
                .listCount(keys.size());
        for (CheckpointKey key : keys) {
            e.string(key.keyId())
                    .string(key.alg())
                    .string(key.publicKey())
                    .string(key.operatorId())
                    .enumName(key.role())
                    .optionalString(key.url());
        }
        return e.toByteArray();
    }

    public static String hash(WitnessRegistryContent content) {
        return CanonicalEncoder.sha256Hex(bytes(content));
    }
}
