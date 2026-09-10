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

/**
 * Verifies routing-policy bundles at two levels:
 * <ol>
 *   <li><b>Authority</b> (governance): k-of-n threshold Ed25519 signatures over the whole canonical bundle.
 *       This attests the bundle including each delegation zone's grant (scope + delegate public key).</li>
 *   <li><b>Delegate</b>: each zone's rules must be signed by that zone's delegate key. A rule is only
 *       trusted when its zone is delegate-verified, so a delegate controls its own rules within its
 *       authority-granted scope. This constrains delegates, not the authority: the authority attests the
 *       delegate key by signing the bundle and no delegate key is pinned, so an authority can publish a
 *       zone whose delegate key it holds (ADM-001 L6 on unreviewed routing authority).</li>
 * </ol>
 */
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

    /**
     * The set of zone ids whose rules carry a valid delegate signature (the delegate key is the one the
     * authority attested in the zone). Assumes the bundle's authority signatures were already verified, so
     * the zone's {@code delegatePublicKey} is trusted. When signatures are not required (dev), every zone id
     * is returned. A rule should only be applied when its zone is in this set.
     */
    public Set<String> delegateVerifiedZones(RoutingPolicyBundle bundle) {
        Set<String> verified = new HashSet<>();
        List<DelegationZone> zones = bundle.delegationZones() == null ? List.of() : bundle.delegationZones();
        if (!requireSignatures) {
            for (DelegationZone z : zones) {
                if (z.id() != null) {
                    verified.add(z.id());
                }
            }
            return verified;
        }
        List<RoutingPolicyBundle.DelegateSignature> sigs =
                bundle.delegateSignatures() == null ? List.of() : bundle.delegateSignatures();
        for (DelegationZone zone : zones) {
            if (zone.id() == null || blank(zone.delegateKeyId()) || blank(zone.delegatePublicKey())) {
                continue;
            }
            PublicKey delegateKey;
            try {
                delegateKey = Ed25519.publicKey(zone.delegatePublicKey());
            } catch (RuntimeException e) {
                continue;   // malformed delegate key -> zone not verified (fail closed)
            }
            byte[] canonical = CanonicalDelegatedRules.bytes(
                    bundle.policyId(), bundle.version(), zone.id(), bundle.rules());
            for (RoutingPolicyBundle.DelegateSignature sig : sigs) {
                if (sig == null || !zone.id().equals(sig.zoneId())
                        || !zone.delegateKeyId().equals(sig.delegateKeyId())) {
                    continue;
                }
                if (Ed25519.verify(delegateKey, canonical, sig.signatureB64())) {
                    verified.add(zone.id());
                    break;
                }
            }
        }
        return verified;
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
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
