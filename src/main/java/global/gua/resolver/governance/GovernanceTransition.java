package global.gua.resolver.governance;

import java.time.Instant;
import java.util.List;

/**
 * One step in the governance key chain (ADM-001 L10): it installs a new key set and threshold, and is
 * co-signed by the old set and the new one.
 *
 * <p>Both thresholds are required, each counted by operator. The old set's threshold is what makes the
 * change authorised; the new set's is what proves the incoming keys exist and are held, so a transition
 * cannot hand governance to a key nobody can use. The chain is linear: {@code index} counts from 1 and
 * {@code previousHash} is the genesis id at index 1 and the previous transition's hash after that, so a
 * transition cannot be reordered, replayed or grafted onto a different genesis.
 *
 * <p>Catastrophic loss of the whole set is not recoverable here and stays ADM-001 O13: with no old-set
 * signatures there is no valid transition, and the answer is a new genesis plus a client re-pin.
 *
 * @param genesisId    the genesis this chain descends from
 * @param index        position in the chain, from 1
 * @param previousHash genesis id at index 1, else the previous transition's hash
 * @param newThreshold the threshold that applies once this transition is applied
 * @param newKeys      the key set that applies once this transition is applied
 * @param signatures   outside the canonical bytes; must satisfy the old and the new threshold
 */
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
