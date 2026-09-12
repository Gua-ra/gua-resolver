package global.gua.resolver.governance;

import java.security.PublicKey;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import global.gua.resolver.crypto.Ed25519;

/**
 * The governance threshold rule: a governance object is valid when valid signatures over its canonical bytes
 * come from at least {@code threshold} <b>distinct operators</b>.
 *
 * <p>It dedupes on {@code operatorId} and never on {@code keyId}. ADM-001 L8 names the shipped
 * {@code RosterVerifier.countValidSignatures} shape ("one vote per authority key") as the defect to avoid:
 * counting keys yields a threshold that one operator holding k keys satisfies alone. Counting operators
 * makes k = 1 at one operator no matter how many keys are listed, which is the true answer. That is also why
 * this class exists separately rather than as a flag on the roster verifier: the roster keeps its per-key
 * counting for the operational snapshot, and no governance threshold may borrow it.
 *
 * <p>At one operator this yields no independence. It yields an honest count, which is the prerequisite for
 * independence later and the thing a second operator turns into a real guarantee.
 */
public final class GovernanceVerifier {

    private GovernanceVerifier() {}

    /**
     * @param operators        distinct operators whose keys produced a valid signature
     * @param threshold        how many were required
     * @param countedOperators which operators were counted, for diagnostics
     */
    public record Outcome(int operators, long threshold, Set<String> countedOperators) {

        public boolean valid() {
            return operators >= threshold;
        }
    }

    /** Count the distinct operators that validly signed {@code canonical}. */
    public static Outcome count(GovernanceKeySet keySet, byte[] canonical,
                                List<GovernanceSignature> signatures) {
        Set<String> operators = new LinkedHashSet<>();
        for (GovernanceSignature signature : signatures == null ? List.<GovernanceSignature>of() : signatures) {
            if (signature == null || signature.keyId() == null || signature.signatureB64() == null) {
                continue;
            }
            GovernanceKey key = keySet.key(signature.keyId());
            PublicKey publicKey = keySet.publicKey(signature.keyId());
            if (key == null || publicKey == null || operators.contains(key.operatorId())) {
                continue;
            }
            if (Ed25519.verify(publicKey, canonical, signature.signatureB64())) {
                operators.add(key.operatorId());
            }
        }
        return new Outcome(operators.size(), keySet.threshold(), Set.copyOf(operators));
    }

    /** Verify or refuse; {@code what} names the object in the failure, for a diagnosable startup error. */
    public static void require(GovernanceKeySet keySet, byte[] canonical,
                               List<GovernanceSignature> signatures, String what) {
        Outcome outcome = count(keySet, canonical, signatures);
        if (!outcome.valid()) {
            throw new GovernanceException(what + " carries valid signatures from " + outcome.operators()
                    + " operator(s), need " + outcome.threshold());
        }
    }
}
