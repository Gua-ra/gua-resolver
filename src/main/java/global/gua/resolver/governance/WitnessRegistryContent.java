package global.gua.resolver.governance;

import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import global.gua.resolver.crypto.Ed25519;

/** The content of a {@code WitnessRegistry} epoch: the keys that sign checkpoints and how many witnesses must. */
public record WitnessRegistryContent(String schema, long requiredWitnesses, List<CheckpointKey> keys) {

    public static final String SCHEMA = "gua-witness-registry-content.v1";

    public WitnessRegistryContent {
        keys = keys == null ? List.of() : List.copyOf(keys);
    }

    public void validateShape() {
        if (!SCHEMA.equals(schema)) {
            throw new GovernanceException("unsupported witness list schema: " + schema);
        }
        Set<String> publicKeys = new HashSet<>();
        for (CheckpointKey key : keys) {
            if (key == null || blank(key.keyId()) || blank(key.publicKey()) || blank(key.operatorId())
                    || key.role() == null) {
                throw new GovernanceException("a checkpoint key needs keyId, publicKey, operatorId and role");
            }
            if (!GovernanceKey.ALG.equals(key.alg())) {
                throw new GovernanceException("unsupported key algorithm: " + key.alg());
            }
            if (key.url() != null && key.url().isBlank()) {
                throw new GovernanceException("url must be absent or non-blank");
            }
            // Compared after decoding, because several base64 spellings decode to the same key.
            if (!publicKeys.add(HexFormat.of().formatHex(decoded(key)))) {
                throw new GovernanceException("a public key is listed once: " + key.keyId());
            }
        }
        if (keys.stream().noneMatch(k -> k.role() == CheckpointKey.Role.RESOLVER)) {
            throw new GovernanceException("the witness list needs at least one resolver key");
        }
        int counted = countedWitnessOperators().size();
        // More than half: any two sets of accepted witness signatures then share an operator.
        if (requiredWitnesses < 0
                || (requiredWitnesses > 0 && (requiredWitnesses > counted || 2 * requiredWitnesses <= counted))) {
            throw new GovernanceException("requiredWitnesses must be 0, or more than half of the " + counted
                    + " witness operators that count");
        }
    }

    /** Operators whose witness signatures count: those holding no resolver key. */
    public Set<String> countedWitnessOperators() {
        Set<String> resolverOperators = keys.stream()
                .filter(k -> k.role() == CheckpointKey.Role.RESOLVER)
                .map(CheckpointKey::operatorId)
                .collect(Collectors.toSet());
        return keys.stream()
                .filter(k -> k.role() == CheckpointKey.Role.WITNESS)
                .map(CheckpointKey::operatorId)
                .filter(operator -> !resolverOperators.contains(operator))
                .collect(Collectors.toSet());
    }

    private static byte[] decoded(CheckpointKey key) {
        try {
            return Ed25519.publicKey(key.publicKey()).getEncoded();
        } catch (IllegalArgumentException e) {
            throw new GovernanceException("invalid public key: " + key.keyId());
        }
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
