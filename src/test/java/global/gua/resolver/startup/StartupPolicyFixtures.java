package global.gua.resolver.startup;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.policy.DelegationZone;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicyRule;
import global.gua.resolver.policy.RoutingPolicySigner;

/**
 * Policy bundles for the startup tests. Every key is minted in memory by the test that uses it, and every
 * bundle is built and signed here: nothing reads a file, a secret or a key from any environment.
 */
final class StartupPolicyFixtures {

    static final String POLICY_ID = "dev-routing";
    static final long VERSION = 2L;
    static final String ZONE_ID = "zone-startup";
    static final String DELEGATE_KEY_ID = "delegate-startup";
    static final String ZONE_SCOPE = "+55119";
    static final String RULE_MATCH = "+551198881";
    static final String PHONE_IN_ZONE = "+5511988812345";

    private StartupPolicyFixtures() {}

    static ObjectMapper mapper() {
        return new ObjectMapper().findAndRegisterModules()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /** A bundle whose one zone and rule route {@link #PHONE_IN_ZONE} to the given member, delegate-signed. */
    static RoutingPolicyBundle routingTo(String homeserverId, Ed25519.KeyPairB64 delegate) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        RoutingPolicyBundle bundle = new RoutingPolicyBundle(
                RoutingPolicyBundle.SCHEMA_VERSION, POLICY_ID, VERSION, now,
                now.minusSeconds(60), now.plusSeconds(3600),
                List.of(new DelegationZone(ZONE_ID, DelegationZone.ScopeType.PHONE_PREFIX, ZONE_SCOPE,
                        "startup:" + homeserverId, DELEGATE_KEY_ID, delegate.publicKeyB64(),
                        List.of(homeserverId), null, null)),
                List.of(new RoutingPolicyRule("rule-startup", 10,
                        RoutingPolicyRule.MatchType.PHONE_PREFIX, RULE_MATCH, null, null,
                        homeserverId, ZONE_ID, "startup contract rule",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true), List.of(), List.of());
        return RoutingPolicySigner.signZone(bundle, ZONE_ID, DELEGATE_KEY_ID, delegate.privateKeyB64());
    }

    /**
     * A bundle with no zones and no rules. It still has to load and verify, so it isolates the trust root
     * from the roster: with governance required the seeded member waits in PENDING, so a bundle that targeted
     * it would fail validation for a reason that has nothing to do with which key signed it.
     *
     * <p>That reason is itself a way this configuration fails to start, so it is not left untested here: it
     * is the subject of {@link GovernedStartupNeedsAnActiveMemberTest}, which uses {@link #routingTo} under
     * governance on purpose. Isolation is why this bundle exists, not an assumption that the other path is
     * safe.
     */
    static RoutingPolicyBundle ruleless() {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        return new RoutingPolicyBundle(RoutingPolicyBundle.SCHEMA_VERSION, POLICY_ID, VERSION, now,
                now.minusSeconds(60), now.plusSeconds(3600), List.of(), List.of(),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true), List.of(), List.of());
    }

    /** Stands in for whoever signs a bundle: the offline governance tool, or the operational key. */
    static RoutingPolicyBundle signedBy(RoutingPolicyBundle bundle, String keyId, String privateKeyB64) {
        ResolverProperties signing = new ResolverProperties();
        signing.getPolicy().setSigningKeyId(keyId);
        signing.getPolicy().setSigningPrivateKey(privateKeyB64);
        return new RoutingPolicySigner(signing).sign(bundle);
    }

    /** Write the bundle where a deployment would mount it, and return the path. */
    static Path write(RoutingPolicyBundle bundle, String prefix) throws Exception {
        Path file = Files.createTempDirectory(prefix).resolve("routing-policy.json");
        Files.writeString(file, mapper().writeValueAsString(bundle));
        return file;
    }

    /** Every message down the cause chain, which is where a startup failure puts its reason. */
    static List<String> causeMessages(Throwable thrown) {
        List<String> messages = new ArrayList<>();
        for (Throwable t = thrown; t != null; t = t.getCause()) {
            if (t.getMessage() != null) {
                messages.add(t.getMessage());
            }
            if (t.getCause() == t) {
                break;
            }
        }
        return messages;
    }
}
