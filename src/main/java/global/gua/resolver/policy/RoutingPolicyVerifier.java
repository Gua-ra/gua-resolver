package global.gua.resolver.policy;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

/** Verifies detached Ed25519 signatures over canonical routing-policy bundles. */
@Component
public class RoutingPolicyVerifier {

    private final int threshold;
    private final boolean requireSignatures;
    private final Map<String, PublicKey> trustedKeys = new HashMap<>();

    public RoutingPolicyVerifier(ResolverProperties props) {
        this.threshold = Math.max(1, props.getPolicy().getSignatureThreshold());
        this.requireSignatures = props.getPolicy().isRequireSignatures();
        List<ResolverProperties.TrustedKey> keys = props.getPolicy().getTrustedKeys().isEmpty()
                ? props.getAuthority().getTrustedKeys()
                : props.getPolicy().getTrustedKeys();
        for (ResolverProperties.TrustedKey k : keys) {
            if (k.getId() != null && k.getPublicKey() != null && !k.getPublicKey().isBlank()) {
                trustedKeys.put(k.getId(), Ed25519.publicKey(k.getPublicKey()));
            }
        }
    }

    public boolean isVerified(RoutingPolicyBundle bundle) {
        if (!requireSignatures) {
            return true;
        }
        return countValidSignatures(bundle) >= threshold;
    }

    public void requireVerified(RoutingPolicyBundle bundle) {
        if (!requireSignatures) {
            return;
        }
        int valid = countValidSignatures(bundle);
        if (valid < threshold) {
            throw new RoutingPolicyVerificationException(
                    "routing policy " + bundle.policyId() + " v" + bundle.version()
                            + " has " + valid + " valid signatures, need " + threshold);
        }
    }

    private int countValidSignatures(RoutingPolicyBundle bundle) {
        byte[] canonical = CanonicalRoutingPolicy.bytes(bundle);
        Set<String> counted = new HashSet<>();
        int valid = 0;
        List<RoutingPolicyBundle.PolicySignature> signatures =
                bundle.signatures() == null ? List.of() : bundle.signatures();
        for (RoutingPolicyBundle.PolicySignature sig : signatures) {
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

    public static class RoutingPolicyVerificationException extends RuntimeException {
        public RoutingPolicyVerificationException(String message) {
            super(message);
        }
    }
}
