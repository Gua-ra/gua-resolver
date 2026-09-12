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

    /** Add (or replace) this node's authority signature over the canonical bundle. */
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
        return withSignatures(unsigned, signatures, unsigned.delegateSignatures());
    }

    public boolean canSign() {
        return keyId != null && !keyId.isBlank() && signingKey != null;
    }

    /**
     * Produce a delegate signature over the rules of one zone and add it to the bundle. The delegate holds
     * {@code delegatePrivateKeyB64}; {@code delegateKeyId} must match the zone's declared delegateKeyId.
     * Used by authoring tooling and tests; the authority still has to sign the bundle around it.
     */
    public static RoutingPolicyBundle signZone(RoutingPolicyBundle bundle, String zoneId,
                                               String delegateKeyId, String delegatePrivateKeyB64) {
        PrivateKey delegateKey = Ed25519.privateKey(delegatePrivateKeyB64);
        byte[] canonical = CanonicalDelegatedRules.bytes(
                bundle.policyId(), bundle.version(), zoneId, bundle.rules());
        var delegateSig = new RoutingPolicyBundle.DelegateSignature(
                zoneId, delegateKeyId, Ed25519.sign(delegateKey, canonical));
        List<RoutingPolicyBundle.DelegateSignature> delegateSigs =
                new ArrayList<>(bundle.delegateSignatures() == null ? List.of() : bundle.delegateSignatures());
        delegateSigs.removeIf(s -> zoneId.equals(s.zoneId()) && delegateKeyId.equals(s.delegateKeyId()));
        delegateSigs.add(delegateSig);
        return withSignatures(bundle, bundle.signatures(), delegateSigs);
    }

    private static RoutingPolicyBundle withSignatures(RoutingPolicyBundle b,
                                                      List<RoutingPolicyBundle.PolicySignature> authority,
                                                      List<RoutingPolicyBundle.DelegateSignature> delegate) {
        return new RoutingPolicyBundle(b.schemaVersion(), b.policyId(), b.version(),
                b.issuedAt(), b.notBefore(), b.expiresAt(), b.delegationZones(),
                b.rules(), b.fallback(), authority, delegate);
    }
}
