package global.gua.resolver.governance;

import java.time.Instant;
import java.util.List;

/** index counts from 1; previousHash is the genesis id at index 1, then the previous transition's hash. */
public record GovernanceTransition(
        String schema,
        String genesisId,
        long index,
        String previousHash,
        Instant issuedAt,
        long newThreshold,
        List<GovernanceKey> newKeys,
        List<GovernanceSignature> signatures) {

    public static final String SCHEMA = "gua-governance-transition.v1";

    public GovernanceTransition {
        newKeys = newKeys == null ? List.of() : List.copyOf(newKeys);
        signatures = signatures == null ? List.of() : List.copyOf(signatures);
    }

    public GovernanceTransition withSignatures(List<GovernanceSignature> newSignatures) {
        return new GovernanceTransition(schema, genesisId, index, previousHash, issuedAt, newThreshold,
                newKeys, newSignatures);
    }

    public void validateShape() {
        if (!SCHEMA.equals(schema)) {
            throw new GovernanceException("unsupported transition schema: " + schema);
        }
        if (genesisId == null || genesisId.isBlank()) {
            throw new GovernanceException("genesisId is required");
        }
        if (index < 1) {
            throw new GovernanceException("transition index starts at 1");
        }
        if (previousHash == null || previousHash.isBlank()) {
            throw new GovernanceException("previousHash is required");
        }
        if (issuedAt == null || issuedAt.getNano() % 1_000_000 != 0) {
            throw new GovernanceException("issuedAt is required at millisecond precision");
        }
        GovernanceKeySet.validateKeys(newKeys, newThreshold);
    }
}
