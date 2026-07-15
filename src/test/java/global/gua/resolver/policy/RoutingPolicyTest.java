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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoutingPolicyTest {

    private static final Homeserver CARRIER = new Homeserver(
            "carrier", "vivo.gua.global", "https://carrier", "https://carrier/auth", "BR", 1, true, "");
    private static final Homeserver UNI = new Homeserver(
            "uni", "usp.gua.global", "https://uni", "https://uni/auth", "BR", 1, true, "");

    private static final Ed25519.KeyPairB64 DELEGATE = Ed25519.generate();

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
                        zoneScope, "carrier:vivo", "delegate-vivo", DELEGATE.publicKeyB64(),
                        List.of(target), null, null)),
                List.of(new RoutingPolicyRule("carrier-rule", 10, RoutingPolicyRule.MatchType.PHONE_PREFIX,
                        ruleMatch, null, null, target, "carrier-zone", "portable delegated carrier rule",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true),
                List.of(), List.of());
    }

    private static ResolverProperties authorityProps(Ed25519.KeyPairB64 key, int threshold) {
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setRequireSignatures(true);
        props.getPolicy().setSignatureThreshold(threshold);
        props.getPolicy().setSigningKeyId("policy-a");
        props.getPolicy().setSigningPrivateKey(key.privateKeyB64());
        ResolverProperties.TrustedKey trusted = new ResolverProperties.TrustedKey();
        trusted.setId("policy-a");
        trusted.setPublicKey(key.publicKeyB64());
        props.getPolicy().setTrustedKeys(List.of(trusted));
        return props;
    }

    @Test
    void signedPolicyVerifiesAndTamperingBreaksIt() {
        Ed25519.KeyPairB64 key = Ed25519.generate();
        ResolverProperties props = authorityProps(key, 1);

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
                signed.fallback(), signed.signatures(), signed.delegateSignatures());

        assertThat(verifier.isVerified(tampered)).isFalse();
    }

    @Test
    void belowThresholdSignaturesAreRejected() {
        Ed25519.KeyPairB64 key = Ed25519.generate();
        ResolverProperties props = authorityProps(key, 2);   // require k=2 distinct valid signatures

        RoutingPolicyBundle signed = new RoutingPolicySigner(props).sign(
                unsignedPolicy("carrier", "+55119", "+551198"));   // carries only one signature
        RoutingPolicyVerifier verifier = new RoutingPolicyVerifier(props);

        assertThat(verifier.isVerified(signed)).isFalse();
        assertThatThrownBy(() -> verifier.requireVerified(signed))
                .isInstanceOf(RoutingPolicyVerifier.RoutingPolicyVerificationException.class)
                .hasMessageContaining("need 2");
    }

    @Test
    void delegateSignedZoneIsDelegateVerified() {
        RoutingPolicyVerifier verifier = new RoutingPolicyVerifier(authorityProps(Ed25519.generate(), 1));
        RoutingPolicyBundle bundle = RoutingPolicySigner.signZone(
                unsignedPolicy("carrier", "+55119", "+551198"),
                "carrier-zone", "delegate-vivo", DELEGATE.privateKeyB64());

        assertThat(verifier.delegateVerifiedZones(bundle)).containsExactly("carrier-zone");
    }

    @Test
    void zoneWithoutADelegateSignatureIsNotDelegateVerified() {
        RoutingPolicyVerifier verifier = new RoutingPolicyVerifier(authorityProps(Ed25519.generate(), 1));

        // authority-signed only, no delegate signature over the zone's rules
        assertThat(verifier.delegateVerifiedZones(unsignedPolicy("carrier", "+55119", "+551198"))).isEmpty();
    }

    @Test
    void authorityCannotForgeADelegatesRules() {
        RoutingPolicyVerifier verifier = new RoutingPolicyVerifier(authorityProps(Ed25519.generate(), 1));
        RoutingPolicyBundle delegateSigned = RoutingPolicySigner.signZone(
                unsignedPolicy("carrier", "+55119", "+551198"),
                "carrier-zone", "delegate-vivo", DELEGATE.privateKeyB64());

        // Whoever assembles the bundle swaps the delegate's rule for a different target, keeping the old
        // delegate signature. The delegate signature is over the ORIGINAL rules, so the zone no longer verifies.
        RoutingPolicyBundle forged = new RoutingPolicyBundle(delegateSigned.schemaVersion(),
                delegateSigned.policyId(), delegateSigned.version(), delegateSigned.issuedAt(),
                delegateSigned.notBefore(), delegateSigned.expiresAt(), delegateSigned.delegationZones(),
                List.of(new RoutingPolicyRule("carrier-rule", 10, RoutingPolicyRule.MatchType.PHONE_PREFIX,
                        "+551198", null, null, "uni", "carrier-zone", "forged target",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                delegateSigned.fallback(), delegateSigned.signatures(), delegateSigned.delegateSignatures());

        assertThat(verifier.delegateVerifiedZones(forged)).isEmpty();
    }

    @Test
    void validatorRejectsZoneWithoutADelegateKey() {
        RoutingPolicyValidator validator = new RoutingPolicyValidator();
        RoutingPolicyBundle policy = new RoutingPolicyBundle(
                RoutingPolicyBundle.SCHEMA_VERSION, "delegated-br", 1, Instant.now(),
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600),
                List.of(new DelegationZone("carrier-zone", DelegationZone.ScopeType.PHONE_PREFIX,
                        "+55119", "carrier:vivo", null, null, List.of("carrier"), null, null)),
                List.of(new RoutingPolicyRule("carrier-rule", 10, RoutingPolicyRule.MatchType.PHONE_PREFIX,
                        "+551198", null, null, "carrier", "carrier-zone", "r",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true), List.of(), List.of());

        assertThatThrownBy(() -> validator.validate(policy, roster()))
                .isInstanceOf(RoutingPolicyValidator.RoutingPolicyValidationException.class)
                .hasMessageContaining("delegateKeyId");
    }

    @Test
    void validatorRejectsRuleOutsideDelegationScope() {
        RoutingPolicyValidator validator = new RoutingPolicyValidator();

        assertThatThrownBy(() -> validator.validate(unsignedPolicy("carrier", "+55119", "+5521"), roster()))
                .isInstanceOf(RoutingPolicyValidator.RoutingPolicyValidationException.class)
                .hasMessageContaining("outside delegation zone");
    }

    @Test
    void validatorAllowsTwoOidcRulesThatDifferOnlyByClaimName() {
        RoutingPolicyValidator validator = new RoutingPolicyValidator();
        String issuer = "https://issuer.example";
        RoutingPolicyBundle policy = new RoutingPolicyBundle(
                RoutingPolicyBundle.SCHEMA_VERSION, "delegated-oidc", 1, Instant.now(),
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600),
                List.of(new DelegationZone("oidc-zone", DelegationZone.ScopeType.OIDC_ISSUER,
                        issuer, "oidc:issuer", "delegate-oidc", DELEGATE.publicKeyB64(),
                        List.of("carrier", "uni"), null, null)),
                List.of(
                        new RoutingPolicyRule("r-groups", 10, RoutingPolicyRule.MatchType.OIDC_CLAIM,
                                "staff", issuer, "groups", "carrier", "oidc-zone", "route by groups",
                                RoutingPolicyRule.AssignmentPolicy.PORTABLE, true),
                        new RoutingPolicyRule("r-department", 20, RoutingPolicyRule.MatchType.OIDC_CLAIM,
                                "staff", issuer, "department", "uni", "oidc-zone", "route by department",
                                RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true), List.of(), List.of());

        // Both rules share matchValue "staff" but read different OIDC claims, so they are genuinely distinct
        // and must not be rejected as ambiguous. The pre-fix ambiguity key ignored issuer/claim and collided
        // them, wrongly failing an otherwise valid institutional policy.
        assertThatCode(() -> validator.validate(policy, roster())).doesNotThrowAnyException();
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
                        "+55119", "carrier:vivo", "delegate-vivo", DELEGATE.publicKeyB64(),
                        List.of("carrier"), null, null)),
                List.of(new RoutingPolicyRule("carrier-rule", 10, RoutingPolicyRule.MatchType.PHONE_PREFIX,
                        "+551198", null, null, "uni", "carrier-zone", "bad target",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true),
                List.of(), List.of());

        assertThatThrownBy(() -> validator.validate(policy, roster()))
                .isInstanceOf(RoutingPolicyValidator.RoutingPolicyValidationException.class)
                .hasMessageContaining("outside delegation zone");
    }
}
