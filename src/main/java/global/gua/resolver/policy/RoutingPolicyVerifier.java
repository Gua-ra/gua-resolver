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

/** Trust root: genesis governance keys when governance is required, else policy keys, then authority keys. */
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

    /** Assumes the bundle's authority signatures are already verified. */
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
