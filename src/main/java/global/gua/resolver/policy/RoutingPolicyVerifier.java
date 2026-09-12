package global.gua.resolver.policy;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.governance.GenesisLoader;
import global.gua.resolver.governance.GovernanceKeySet;

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
 *
 * <p><b>Which trust root is in force follows {@code gua.resolver.governance.required}, and nothing else.</b>
 *
 * <ul>
 *   <li><b>Flag off (the default).</b> Bundles verify under {@code policy.trusted-keys}, or, when that list
 *       is unset, under {@code authority.trusted-keys}. That fallback lets the operational roster-signing
 *       key attest policy, which is exactly the key-role sharing ADM-001 L8 wants gone, and it is kept here
 *       only because it is what an environment that has not run the key ceremony is already serving on.</li>
 *   <li><b>Flag on.</b> The governance key set from the pinned genesis is the only trust root. Both
 *       fallbacks are gone and a bundle signed by the operational key is refused.</li>
 * </ul>
 *
 * <p>The gate is the correction to how this shipped the first time. The fail-closed root was applied
 * unconditionally, so an environment whose bundle was signed with the operational key stopped verifying its
 * own policy at startup: {@code FileRoutingPolicySource} throws from its constructor when no bundle loads,
 * so the context never started and the service crash-looped. A trust root is chosen at startup, so widening
 * or narrowing it is a deploy-time event that has to be tied to the same flag the operator flips
 * deliberately, and tested by booting the application (see {@code global.gua.resolver.startup}).
 *
 * <p>Signature counting here still dedupes by key id, which is the shipped envelope's shape. That is
 * tolerable only because policy is a single-operator key set today and no independence claim rests on it;
 * a threshold that has to mean independence uses {@code GovernanceVerifier}, which counts operators
 * (ADM-001 L8). Do not reuse this counter for one.
 */
@Component
public class RoutingPolicyVerifier {

    private static final Logger log = LoggerFactory.getLogger(RoutingPolicyVerifier.class);

    private final int threshold;
    private final boolean requireSignatures;
    private final Map<String, PublicKey> trustedKeys = new HashMap<>();

    @Autowired
    public RoutingPolicyVerifier(ResolverProperties props, GenesisLoader genesis) {
        this(props, genesis.keySet().orElse(null));
    }

    /**
     * Without a genesis, as an offline verifier or a test configures it. With governance required and no
     * governance key set to require signatures from, this holds no keys and verifies nothing.
     */
    public RoutingPolicyVerifier(ResolverProperties props) {
        this(props, (GovernanceKeySet) null);
    }

    private RoutingPolicyVerifier(ResolverProperties props, GovernanceKeySet governance) {
        this.threshold = Math.max(1, props.getPolicy().getSignatureThreshold());
        this.requireSignatures = props.getPolicy().isRequireSignatures();
        boolean governanceRequired = props.getGovernance().isRequired();

        List<ResolverProperties.TrustedKey> keys;
        String root;
        if (governanceRequired) {
            keys = governance == null ? List.of() : governance.asTrustedKeys();
            root = "the federation genesis governance key set";
        } else if (!props.getPolicy().getTrustedKeys().isEmpty()) {
            keys = props.getPolicy().getTrustedKeys();
            root = "gua.resolver.policy.trusted-keys";
        } else {
            keys = props.getAuthority().getTrustedKeys();
            root = "gua.resolver.authority.trusted-keys (the pre-cutover fallback)";
        }
        for (ResolverProperties.TrustedKey k : keys) {
            if (k.getId() != null && k.getPublicKey() != null && !k.getPublicKey().isBlank()) {
                trustedKeys.put(k.getId(), Ed25519.publicKey(k.getPublicKey()));
            }
        }

        if (!requireSignatures) {
            log.warn("Routing-policy signatures are NOT required (gua.resolver.policy.require-signatures is "
                    + "false): every bundle is accepted unverified");
        } else if (trustedKeys.isEmpty()) {
            log.warn("No routing-policy trust root: {} holds no usable key, so every policy bundle will be "
                    + "rejected and a file policy source will refuse to start. With governance required "
                    + "({}), configure the genesis the bundle was signed under (ADM-001 L8)",
                    root, governanceRequired);
        } else {
            // Logged at every startup because it is the fact that decides whether a deployed bundle loads.
            log.info("Routing-policy trust root: {} ({} key(s), threshold {}, governance required: {})",
                    root, trustedKeys.size(), threshold, governanceRequired);
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
