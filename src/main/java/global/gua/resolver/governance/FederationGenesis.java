package global.gua.resolver.governance;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * The pinned root of the federation's trust chain: a threshold set of governance keys, the registries that
 * hang beneath them, and the label the federation goes by.
 *
 * <p>v1 is signed by the keys it enumerates, so verifying a genesis against itself proves only that its own
 * keys signed it. It has to travel out of band: pinned in first-party builds, published at a well-known
 * location, and compared by fingerprint across independent channels.
 *
 * <p>{@code federationLabel} is a label; the identity is {@code genesisId}, the SHA-256 of the canonical
 * bytes.
 *
 * @param federationLabel  human label for the environment, for example {@code gua.global} or {@code gua-dev}
 * @param createdAt        creation time, millisecond precision
 * @param hashSuite        {@code SHA-256}
 * @param threshold        governance k: how many distinct operators must sign a governance act
 * @param keys             the enumerated governance keys, each recording the operator that holds it
 * @param registries       the registry names, fixed in v1 to the four in {@link Registry}. They are a set:
 *                         the JSON list order is not significant and the canonical bytes sort them
 * @param signatures       outside the canonical bytes; at least {@code threshold} from distinct operators
 */
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

    /**
     * Structural validation, before any signature is checked: a malformed genesis is refused rather than
     * counted against a threshold it could never meet honestly.
     */
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
        // Compared as a set, because a set is what the canonical bytes encode: two genesis files listing the
        // four names in different orders have identical bytes and the same genesisId. Duplicates are still
        // refused, which a set comparison on its own would hide.
        if (registries.size() != Set.copyOf(registries).size()
                || !Set.copyOf(registries).equals(Set.copyOf(Registry.allWireNames()))) {
            throw new GovernanceException("a v1 genesis enumerates exactly " + Registry.allWireNames()
                    + ", in any order and without duplicates");
        }
        GovernanceKeySet.validateKeys(keys, threshold);
    }
}
