package global.gua.resolver.policy;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

/** Optional helper for nodes that are allowed to produce policy signatures. */
@Component
public class RoutingPolicySigner {

    private final String keyId;
    private final PrivateKey signingKey;

    public RoutingPolicySigner(ResolverProperties props) {
        String configuredKeyId = props.getPolicy().getSigningKeyId();
        String configuredPrivateKey = props.getPolicy().getSigningPrivateKey();
        if (configuredKeyId == null || configuredKeyId.isBlank()) {
            configuredKeyId = props.getAuthority().getSigningKeyId();
        }
        if (configuredPrivateKey == null || configuredPrivateKey.isBlank()) {
            configuredPrivateKey = props.getAuthority().getSigningPrivateKey();
        }
        this.keyId = configuredKeyId;
        this.signingKey = (configuredPrivateKey == null || configuredPrivateKey.isBlank())
                ? null
                : Ed25519.privateKey(configuredPrivateKey);
    }

    public RoutingPolicyBundle sign(RoutingPolicyBundle unsigned) {
        if (!canSign()) {
            return unsigned;
        }
        byte[] canonical = CanonicalRoutingPolicy.bytes(unsigned);
        var signature = new RoutingPolicyBundle.PolicySignature(keyId, Ed25519.sign(signingKey, canonical));
        List<RoutingPolicyBundle.PolicySignature> signatures =
                new ArrayList<>(unsigned.signatures() == null ? List.of() : unsigned.signatures());
        signatures.removeIf(s -> s.authorityKeyId().equals(signature.authorityKeyId()));
        signatures.add(signature);
        return new RoutingPolicyBundle(unsigned.schemaVersion(), unsigned.policyId(), unsigned.version(),
                unsigned.issuedAt(), unsigned.notBefore(), unsigned.expiresAt(), unsigned.delegationZones(),
                unsigned.rules(), unsigned.fallback(), signatures);
    }

    public boolean canSign() {
        return keyId != null && !keyId.isBlank() && signingKey != null;
    }
}
