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

/**
 * The admin policy surface validates and no longer signs (Phase 2, ADM-001 L8): bundles are signed offline
 * with the governance key. What is checked here is that an operator can still learn, before publishing,
 * everything the resolver will make of a bundle, including whether its signatures verify under the keys this
 * resolver trusts. That last answer is the one that keeps a bundle still signed by the retired operational
 * key from being discovered at startup, when the policy source refuses to load and the service will not come
 * up.
 */
class PolicyAdminControllerTest {

    private static final Ed25519.KeyPairB64 GOVERNANCE = Ed25519.generate();
    private static final Ed25519.KeyPairB64 RETIRED_OPERATIONAL = Ed25519.generate();
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

    /** The resolver's policy trust root: the governance key, and nothing else. */
    private static ResolverProperties props() {
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setRequireSignatures(true);
        props.getPolicy().setSignatureThreshold(1);
        ResolverProperties.TrustedKey trusted = new ResolverProperties.TrustedKey();
        trusted.setId("governance-a");
        trusted.setPublicKey(GOVERNANCE.publicKeyB64());
        props.getPolicy().setTrustedKeys(List.of(trusted));
        return props;
    }

    /** Stand-in for the offline governance tool: sign a bundle with a given key under a given id. */
    private static RoutingPolicyBundle signedBy(RoutingPolicyBundle bundle, String keyId,
                                                Ed25519.KeyPairB64 key) {
        ResolverProperties signing = new ResolverProperties();
        signing.getPolicy().setSigningKeyId(keyId);
        signing.getPolicy().setSigningPrivateKey(key.privateKeyB64());
        return new RoutingPolicySigner(signing).sign(bundle);
    }

    private static PolicyAdminController controller(SignedRoster roster, ResolverProperties props) {
        RosterStore store = new RosterStore() {
            @Override
            public SignedRoster current() { return roster; }

            @Override
            public SignedRoster refresh() { return roster; }
        };
        return new PolicyAdminController(new RoutingPolicyValidator(),
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
    void validatesAGovernanceSignedBundleAndReportsTheZoneAsDelegateVerified() {
        RoutingPolicyBundle delegateSigned = RoutingPolicySigner.signZone(
                unsignedBundle("dev2"), "zone-test", "delegate-dev2", DELEGATE.privateKeyB64());
        RoutingPolicyBundle governanceSigned = signedBy(delegateSigned, "governance-a", GOVERNANCE);

        PolicyAdminController.ValidatedPolicyResponse response =
                controller(roster(DEV, DEV2), props()).validate(governanceSigned);

        assertThat(response.structureValid()).isTrue();
        assertThat(response.signaturesVerified()).isTrue();
        assertThat(response.delegateVerifiedZones()).containsExactly("zone-test");
    }

    @Test
    void aBundleStillSignedByTheRetiredOperationalKeyIsReportedUnverified() {
        // This is the Phase 2 deploy hazard caught early: the bundle is structurally fine and its zone is
        // delegate-signed, but its signature is worthless to this resolver, and a restart would fail.
        RoutingPolicyBundle delegateSigned = RoutingPolicySigner.signZone(
                unsignedBundle("dev2"), "zone-test", "delegate-dev2", DELEGATE.privateKeyB64());
        RoutingPolicyBundle staleSigned = signedBy(delegateSigned, "authority-a", RETIRED_OPERATIONAL);

        PolicyAdminController.ValidatedPolicyResponse response =
                controller(roster(DEV, DEV2), props()).validate(staleSigned);

        assertThat(response.structureValid()).isTrue();
        assertThat(response.signaturesVerified()).isFalse();
        assertThat(response.delegateVerifiedZones()).containsExactly("zone-test");
    }

    @Test
    void aZoneWithoutItsDelegateSignatureValidatesButIsReportedUnverified() {
        PolicyAdminController.ValidatedPolicyResponse response = controller(roster(DEV, DEV2), props())
                .validate(signedBy(unsignedBundle("dev2"), "governance-a", GOVERNANCE));

        assertThat(response.signaturesVerified()).isTrue();
        assertThat(response.delegateVerifiedZones()).isEmpty();
    }

    @Test
    void refusesToValidateABundleTargetingAHomeserverOutsideTheRoster() {
        // dev2 is NOT in the roster: validation rejects it regardless of who signed it.
        assertThatThrownBy(() -> controller(roster(DEV), props())
                .validate(signedBy(unsignedBundle("dev2"), "governance-a", GOVERNANCE)))
                .isInstanceOf(RoutingPolicyValidator.RoutingPolicyValidationException.class)
                .hasMessageContaining("unknown or inactive homeserver");
    }

    @Test
    void withNoPolicyTrustRootConfiguredEveryBundleIsUnverified() {
        // No genesis, no policy.trusted-keys and no authority.trusted-keys: there is no key to verify under,
        // so nothing verifies whatever the flag says.
        ResolverProperties noKeys = new ResolverProperties();
        noKeys.getPolicy().setRequireSignatures(true);
        noKeys.getPolicy().setSignatureThreshold(1);
        RoutingPolicyBundle signed = signedBy(unsignedBundle("dev2"), "governance-a", GOVERNANCE);

        assertThat(controller(roster(DEV, DEV2), noKeys).validate(signed).signaturesVerified()).isFalse();
    }

    @Test
    void beforeTheCutoverTheSameOperationalKeyBundleIsReportedVerified() {
        // The honest answer for an environment that has not flipped gua.resolver.governance.required: with no
        // policy.trusted-keys, the operational key set is still the policy trust root, so this bundle both
        // verifies here and loads at startup. This is the state the deploy hazard above is measured against,
        // and validate must describe the resolver the operator is actually running, not the one they are
        // heading towards.
        ResolverProperties preCutover = new ResolverProperties();
        preCutover.getPolicy().setRequireSignatures(true);
        preCutover.getPolicy().setSignatureThreshold(1);
        ResolverProperties.TrustedKey operational = new ResolverProperties.TrustedKey();
        operational.setId("authority-a");
        operational.setPublicKey(RETIRED_OPERATIONAL.publicKeyB64());
        preCutover.getAuthority().setTrustedKeys(List.of(operational));

        RoutingPolicyBundle staleSigned = signedBy(unsignedBundle("dev2"), "authority-a", RETIRED_OPERATIONAL);

        assertThat(controller(roster(DEV, DEV2), preCutover).validate(staleSigned).signaturesVerified())
                .isTrue();
    }
}
