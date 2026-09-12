package global.gua.resolver.verify;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.policy.DelegationZone;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicyRule;
import global.gua.resolver.policy.RoutingPolicySigner;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterSigner;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The reference client verifier verifies signed artifacts and independently reproduces the resolver's
 * new-account decision, so a client never has to trust the resolver's answer.
 */
class ResolverVerifierTest {

    private static final Ed25519.KeyPairB64 AUTH = Ed25519.generate();
    private static final Ed25519.KeyPairB64 DELEGATE = Ed25519.generate();

    private static final Homeserver CARRIER = new Homeserver(
            "carrier", "vivo.gua.global", "https://carrier", "https://carrier/auth", "BR", 1, true, "");
    private static final Homeserver DEFAULT = new Homeserver(
            "default", "gua.global", "https://default", "https://default/auth", null, 5, true, "");

    private static List<ResolverProperties.TrustedKey> authorityKeys() {
        ResolverProperties.TrustedKey k = new ResolverProperties.TrustedKey();
        k.setId("auth-a");
        k.setPublicKey(AUTH.publicKeyB64());
        return List.of(k);
    }

    private static SignedRoster signedRoster() {
        ResolverProperties props = new ResolverProperties();
        props.getAuthority().setSigningKeyId("auth-a");
        props.getAuthority().setSigningPrivateKey(AUTH.privateKeyB64());
        List<RosterEntry> entries = List.of(
                new RosterEntry(CARRIER, List.of(), Instant.now(), RosterEntry.Status.ACTIVE),
                new RosterEntry(DEFAULT, List.of(), Instant.now(), RosterEntry.Status.ACTIVE));
        return new RosterSigner(props).sign(2, Instant.now(), entries,
                new SignedRoster.LogCheckpoint("root", 2));
    }

    private static RoutingPolicyBundle signedPolicy(boolean delegateSign) {
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setSigningKeyId("auth-a");
        props.getPolicy().setSigningPrivateKey(AUTH.privateKeyB64());
        RoutingPolicyBundle unsigned = new RoutingPolicyBundle(
                RoutingPolicyBundle.SCHEMA_VERSION, "br-policy", 3, Instant.now(),
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600),
                List.of(new DelegationZone("vivo-sp", DelegationZone.ScopeType.PHONE_PREFIX,
                        "+55119", "carrier:vivo", "delegate-vivo", DELEGATE.publicKeyB64(),
                        List.of("carrier"), null, null)),
                List.of(new RoutingPolicyRule("vivo-rule", 10, RoutingPolicyRule.MatchType.PHONE_PREFIX,
                        "+551198", null, null, "carrier", "vivo-sp", "carrier route",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true), List.of(), List.of());
        RoutingPolicyBundle authoritySigned = new RoutingPolicySigner(props).sign(unsigned);
        return delegateSign
                ? RoutingPolicySigner.signZone(authoritySigned, "vivo-sp", "delegate-vivo", DELEGATE.privateKeyB64())
                : authoritySigned;
    }

    private static ResolverVerifier verifier() {
        return new ResolverVerifier(authorityKeys(), 1, authorityKeys(), 1);
    }

    @Test
    void verifiesSignedArtifactsAndReproducesTheRegisterDecision() {
        SignedRoster roster = signedRoster();
        RoutingPolicyBundle policy = signedPolicy(true);
        ResolverVerifier verifier = verifier();

        verifier.verifyRoster(roster);
        verifier.verifyPolicy(policy);

        var ctx = PlacementContext.forPhone("+5511987654321");   // matches +551198 -> carrier
        assertThat(verifier.reproduceNewAccountPlacement(ctx, roster, policy).id()).isEqualTo("carrier");
        assertThat(verifier.verifyRegisterDecision("carrier", ctx, roster, policy)).isTrue();
        assertThat(verifier.verifyRegisterDecision("default", ctx, roster, policy)).isFalse();
    }

    @Test
    void rejectsATamperedRoster() {
        SignedRoster roster = signedRoster();
        // swap in a different homeserver weight while keeping the old authority signature
        Homeserver tampered = new Homeserver("carrier", "vivo.gua.global", "https://carrier",
                "https://carrier/auth", "BR", 999, true, "");
        SignedRoster forged = new SignedRoster(roster.version(), roster.issuedAt(),
                List.of(new RosterEntry(tampered, List.of(), Instant.now(), RosterEntry.Status.ACTIVE)),
                roster.logCheckpoint(), roster.authoritySignatures());

        assertThatThrownBy(() -> verifier().verifyRoster(forged))
                .isInstanceOf(global.gua.resolver.roster.RosterVerifier.RosterVerificationException.class);
    }

    @Test
    void rejectsAPolicyNotSignedByATrustedAuthority() {
        Ed25519.KeyPairB64 stranger = Ed25519.generate();
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setSigningKeyId("auth-a");
        props.getPolicy().setSigningPrivateKey(stranger.privateKeyB64());   // wrong key, right id
        RoutingPolicyBundle unsigned = new RoutingPolicyBundle(
                RoutingPolicyBundle.SCHEMA_VERSION, "br-policy", 3, Instant.now(),
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600),
                List.of(new DelegationZone("vivo-sp", DelegationZone.ScopeType.PHONE_PREFIX,
                        "+55119", "carrier:vivo", "delegate-vivo", DELEGATE.publicKeyB64(),
                        List.of("carrier"), null, null)),
                List.of(), new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true),
                List.of(), List.of());
        RoutingPolicyBundle badlySigned = new RoutingPolicySigner(props).sign(unsigned);

        assertThatThrownBy(() -> verifier().verifyPolicy(badlySigned))
                .isInstanceOf(global.gua.resolver.policy.RoutingPolicyVerifier.RoutingPolicyVerificationException.class);
    }
}
