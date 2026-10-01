package global.gua.resolver.governance;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/** Signed by the keys it enumerates, so it needs an out-of-band pin. The identity is genesisId. */
public record FederationGenesis(
        String schema,
        String federationLabel,
        Instant createdAt,
        String hashSuite,
        long threshold,
        List<GovernanceKey> keys,
        List<String> registries,
        List<GovernanceSignature> signatures) {

    public static final String SCHEMA = "gua-federation-genesis.v1";
    public static final String HASH_SUITE = "SHA-256";

    public FederationGenesis {
        keys = keys == null ? List.of() : List.copyOf(keys);
        registries = registries == null ? List.of() : List.copyOf(registries);
        signatures = signatures == null ? List.of() : List.copyOf(signatures);
    }

    public FederationGenesis withSignatures(List<GovernanceSignature> newSignatures) {
        return new FederationGenesis(schema, federationLabel, createdAt, hashSuite, threshold, keys,
                registries, newSignatures);
    }

    public void validateShape() {
        if (!SCHEMA.equals(schema)) {
            throw new GovernanceException("unsupported genesis schema: " + schema);
        }
        if (!HASH_SUITE.equals(hashSuite)) {
            throw new GovernanceException("unsupported hash suite: " + hashSuite);
        }
        if (federationLabel == null || federationLabel.isBlank()) {
            throw new GovernanceException("federationLabel is required");
        }
        if (createdAt == null || createdAt.getNano() % 1_000_000 != 0) {
            throw new GovernanceException("createdAt is required at millisecond precision");
        }
        // Compared as a set because the canonical bytes encode a set; duplicates are still refused.
        if (registries.size() != Set.copyOf(registries).size()
                || !Set.copyOf(registries).equals(Set.copyOf(Registry.allWireNames()))) {
            throw new GovernanceException("a v1 genesis enumerates exactly " + Registry.allWireNames()
                    + ", in any order and without duplicates");
        }
        GovernanceKeySet.validateKeys(keys, threshold);
    }
}
