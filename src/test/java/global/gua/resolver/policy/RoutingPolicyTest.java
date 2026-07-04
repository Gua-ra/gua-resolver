package global.gua.resolver.policy;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoutingPolicyTest {

    private static final Homeserver CARRIER = new Homeserver(
            "carrier", "vivo.gua.global", "https://carrier", "https://carrier/auth", "BR", 1, true, "");
    private static final Homeserver UNI = new Homeserver(
            "uni", "usp.gua.global", "https://uni", "https://uni/auth", "BR", 1, true, "");

    private static SignedRoster roster() {
        return new SignedRoster(2, Instant.now(),
                List.of(entry(CARRIER), entry(UNI)),
                new SignedRoster.LogCheckpoint("root", 2), List.of());
    }

    private static RosterEntry entry(Homeserver hs) {
        return new RosterEntry(hs, List.of(), Instant.now(), RosterEntry.Status.ACTIVE);
    }

    private static RoutingPolicyBundle unsignedPolicy(String target, String zoneScope, String ruleMatch) {
        return new RoutingPolicyBundle(
                RoutingPolicyBundle.SCHEMA_VERSION,
                "delegated-br",
                1,
                Instant.now(),
                Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600),
                List.of(new DelegationZone("carrier-zone", DelegationZone.ScopeType.PHONE_PREFIX,
                        zoneScope, "carrier:vivo", List.of(target), null, null)),
                List.of(new RoutingPolicyRule("carrier-rule", 10, RoutingPolicyRule.MatchType.PHONE_PREFIX,
                        ruleMatch, null, null, target, "carrier-zone", "portable delegated carrier rule",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true),
                List.of());
    }

    @Test
    void signedPolicyVerifiesAndTamperingBreaksIt() {
        Ed25519.KeyPairB64 key = Ed25519.generate();
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setRequireSignatures(true);
        props.getPolicy().setSignatureThreshold(1);
        props.getPolicy().setSigningKeyId("policy-a");
        props.getPolicy().setSigningPrivateKey(key.privateKeyB64());
        ResolverProperties.TrustedKey trusted = new ResolverProperties.TrustedKey();
        trusted.setId("policy-a");
        trusted.setPublicKey(key.publicKeyB64());
        props.getPolicy().setTrustedKeys(List.of(trusted));

        RoutingPolicyBundle signed = new RoutingPolicySigner(props).sign(
                unsignedPolicy("carrier", "+55119", "+551198"));
        RoutingPolicyVerifier verifier = new RoutingPolicyVerifier(props);

        assertThat(verifier.isVerified(signed)).isTrue();

        RoutingPolicyBundle tampered = new RoutingPolicyBundle(signed.schemaVersion(), signed.policyId(),
                signed.version(), signed.issuedAt(), signed.notBefore(), signed.expiresAt(),
                signed.delegationZones(),
                List.of(new RoutingPolicyRule("carrier-rule", 10, RoutingPolicyRule.MatchType.PHONE_PREFIX,
                        "+551198", null, null, "uni", "carrier-zone", "tampered",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                signed.fallback(), signed.signatures());

        assertThat(verifier.isVerified(tampered)).isFalse();
    }

    @Test
    void validatorRejectsRuleOutsideDelegationScope() {
        RoutingPolicyValidator validator = new RoutingPolicyValidator();

        assertThatThrownBy(() -> validator.validate(unsignedPolicy("carrier", "+55119", "+5521"), roster()))
                .isInstanceOf(RoutingPolicyValidator.RoutingPolicyValidationException.class)
                .hasMessageContaining("outside delegation zone");
    }

    @Test
    void validatorRejectsTargetOutsideDelegationAllowedHomeservers() {
        RoutingPolicyValidator validator = new RoutingPolicyValidator();

        RoutingPolicyBundle policy = new RoutingPolicyBundle(
                RoutingPolicyBundle.SCHEMA_VERSION,
                "delegated-br",
                1,
                Instant.now(),
                Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600),
                List.of(new DelegationZone("carrier-zone", DelegationZone.ScopeType.PHONE_PREFIX,
                        "+55119", "carrier:vivo", List.of("carrier"), null, null)),
                List.of(new RoutingPolicyRule("carrier-rule", 10, RoutingPolicyRule.MatchType.PHONE_PREFIX,
                        "+551198", null, null, "uni", "carrier-zone", "bad target",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true),
                List.of());

        assertThatThrownBy(() -> validator.validate(policy, roster()))
                .isInstanceOf(RoutingPolicyValidator.RoutingPolicyValidationException.class)
                .hasMessageContaining("outside delegation zone");
    }
}
