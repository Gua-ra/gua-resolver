package global.gua.resolver.roster;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

/**
 * Verifies that a {@link SignedRoster} carries at least {@code k} valid authority signatures (k-of-n
 * threshold, §5) over its canonical bytes, each from a distinct published authority key. This is the
 * "verify-on-read" gate every resolver — authority OR mirror — runs before trusting any roster entry, so
 * a single corrupt authority (or a tampered mirror feed) cannot inject a homeserver.
 */
@Component
public class RosterVerifier {

    private final int threshold;
    private final Map<String, PublicKey> trustedKeys = new HashMap<>();

    public RosterVerifier(ResolverProperties props) {
        this.threshold = Math.max(1, props.getAuthority().getThreshold());
        for (ResolverProperties.TrustedKey k : props.getAuthority().getTrustedKeys()) {
            if (k.getId() != null && k.getPublicKey() != null && !k.getPublicKey().isBlank()) {
                trustedKeys.put(k.getId(), Ed25519.publicKey(k.getPublicKey()));
            }
        }
    }

    public boolean isVerified(SignedRoster roster) {
        return countValidSignatures(roster) >= threshold;
    }

    /** Verify or throw — use on the trust boundary (mirror pull, roster load). */
    public void requireVerified(SignedRoster roster) {
        int valid = countValidSignatures(roster);
        if (valid < threshold) {
            throw new RosterVerificationException(
                    "roster v" + roster.version() + " has " + valid
                            + " valid authority signatures, need " + threshold);
        }
    }

    private int countValidSignatures(SignedRoster roster) {
        byte[] canonical = CanonicalRoster.bytes(roster);
        Set<String> counted = new HashSet<>();   // one vote per authority key
        int valid = 0;
        for (SignedRoster.AuthoritySignature sig : roster.authoritySignatures()) {
            PublicKey key = trustedKeys.get(sig.authorityKeyId());
            if (key == null || counted.contains(sig.authorityKeyId())) {
                continue;
            }
            if (Ed25519.verify(key, canonical, sig.signatureB64())) {
                counted.add(sig.authorityKeyId());
                valid++;
            }
        }
        return valid;
    }

    public int threshold() {
        return threshold;
    }

    public static class RosterVerificationException extends RuntimeException {
        public RosterVerificationException(String message) {
            super(message);
        }
    }
}
