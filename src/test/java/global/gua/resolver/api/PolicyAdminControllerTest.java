package global.gua.resolver.api;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.policy.DelegationZone;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicyRule;
import global.gua.resolver.policy.RoutingPolicySigner;
import global.gua.resolver.policy.RoutingPolicyValidator;
import global.gua.resolver.policy.RoutingPolicyVerifier;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyAdminControllerTest {

    private static final Ed25519.KeyPairB64 AUTHORITY = Ed25519.generate();
    private static final Ed25519.KeyPairB64 DELEGATE = Ed25519.generate();

    private static final Homeserver DEV = new Homeserver(
            "dev", "dev.gua.local", "https://dev", "https://dev/auth", "dev", 1, true, "");
    private static final Homeserver DEV2 = new Homeserver(
            "dev2", "dev2.gua.local", "https://dev2", "https://dev2/auth", "dev", 0, true, "");

    private static SignedRoster roster(Homeserver... entries) {
        return new SignedRoster(1, Instant.now(),
                List.of(entries).stream()
                        .map(hs -> new RosterEntry(hs, List.of(), Instant.now(), RosterEntry.Status.ACTIVE))
                        .toList(),
                new SignedRoster.LogCheckpoint("root", entries.length), List.of());
    }

    private static ResolverProperties props() {
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setRequireSignatures(true);
        props.getPolicy().setSignatureThreshold(1);
        props.getPolicy().setSigningKeyId("authority-a");
        props.getPolicy().setSigningPrivateKey(AUTHORITY.privateKeyB64());
        ResolverProperties.TrustedKey trusted = new ResolverProperties.TrustedKey();
        trusted.setId("authority-a");
        trusted.setPublicKey(AUTHORITY.publicKeyB64());
        props.getPolicy().setTrustedKeys(List.of(trusted));
        return props;
    }

    private static PolicyAdminController controller(SignedRoster roster, ResolverProperties props) {
        RosterStore store = new RosterStore() {
            @Override
            public SignedRoster current() { return roster; }

            @Override
            public SignedRoster refresh() { return roster; }
        };
        return new PolicyAdminController(new RoutingPolicyValidator(), new RoutingPolicySigner(props),
                new RoutingPolicyVerifier(props), store);
    }

    private static RoutingPolicyBundle unsignedBundle(String target) {
        Instant now = Instant.now();
        return new RoutingPolicyBundle(RoutingPolicyBundle.SCHEMA_VERSION, "dev-routing", 1,
                now, now.minusSeconds(60), now.plusSeconds(3600),
                List.of(new DelegationZone("zone-test", DelegationZone.ScopeType.PHONE_PREFIX,
                        "+55119888", "test:dev2", "delegate-dev2", DELEGATE.publicKeyB64(),
                        List.of(target), null, null)),
                List.of(new RoutingPolicyRule("rule-test", 10, RoutingPolicyRule.MatchType.PHONE_PREFIX,
                        "+55119888", null, null, target, "zone-test", "testbed prefix",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true),
                List.of(), List.of());
    }

    @Test
    void signsAValidDelegateSignedBundleAndReportsTheZoneAsDelegateVerified() {
        ResolverProperties props = props();
        RoutingPolicyBundle delegateSigned = RoutingPolicySigner.signZone(
                unsignedBundle("dev2"), "zone-test", "delegate-dev2", DELEGATE.privateKeyB64());

        PolicyAdminController.SignedPolicyResponse response =
                controller(roster(DEV, DEV2), props()).sign(delegateSigned);

        assertThat(response.policy().signatures()).hasSize(1);
        assertThat(response.policy().signatures().get(0).authorityKeyId()).isEqualTo("authority-a");
        assertThat(new RoutingPolicyVerifier(props).isVerified(response.policy())).isTrue();
        assertThat(response.delegateVerifiedZones()).containsExactly("zone-test");
    }

    @Test
    void aZoneWithoutItsDelegateSignatureSignsButIsReportedUnverified() {
        PolicyAdminController.SignedPolicyResponse response =
                controller(roster(DEV, DEV2), props()).sign(unsignedBundle("dev2"));

        // The authority signature is applied, but the operator can see the zone will not route.
        assertThat(response.policy().signatures()).hasSize(1);
        assertThat(response.delegateVerifiedZones()).isEmpty();
    }

    @Test
    void refusesToSignABundleTargetingAHomeserverOutsideTheRoster() {
        // dev2 is NOT in the roster: validation must reject before any signature is produced.
        assertThatThrownBy(() -> controller(roster(DEV), props()).sign(unsignedBundle("dev2")))
                .isInstanceOf(RoutingPolicyValidator.RoutingPolicyValidationException.class)
                .hasMessageContaining("unknown or inactive homeserver");
    }
}
