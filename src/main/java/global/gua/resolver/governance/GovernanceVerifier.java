package global.gua.resolver.governance;

import java.security.PublicKey;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import global.gua.resolver.crypto.Ed25519;

/** Counts distinct operators with a valid signature, never keys. */
public final class GovernanceVerifier {

    private GovernanceVerifier() {}

    public record Outcome(int operators, long threshold, Set<String> countedOperators) {

        public boolean valid() {
            return operators >= threshold;
        }
    }

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

    public static void require(GovernanceKeySet keySet, byte[] canonical,
                               List<GovernanceSignature> signatures, String what) {
        Outcome outcome = count(keySet, canonical, signatures);
        if (!outcome.valid()) {
            throw new GovernanceException(what + " carries valid signatures from " + outcome.operators()
                    + " operator(s), need " + outcome.threshold());
        }
    }
}
