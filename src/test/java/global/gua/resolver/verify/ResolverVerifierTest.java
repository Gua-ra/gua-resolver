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
 *
 * <p>The two trust roots are deliberately different keys here. Before Phase 2 this test passed the authority
 * keys as the policy keys, which the fallback made indistinguishable from having no policy keys at all; with
 * the fallback gone, a port that conflates them fails.
 */
class ResolverVerifierTest {

    private static final Ed25519.KeyPairB64 AUTH = Ed25519.generate();
    private static final Ed25519.KeyPairB64 GOVERNANCE = Ed25519.generate();
    private static final Ed25519.KeyPairB64 DELEGATE = Ed25519.generate();

    private static final Homeserver CARRIER = new Homeserver(
            "carrier", "vivo.gua.global", "https://carrier", "https://carrier/auth", "BR", 1, true, "");
    private static final Homeserver DEFAULT = new Homeserver(
            "default", "gua.global", "https://default", "https://default/auth", null, 5, true, "");

    private static List<ResolverProperties.TrustedKey> keys(String id, Ed25519.KeyPairB64 pair) {
        ResolverProperties.TrustedKey k = new ResolverProperties.TrustedKey();
        k.setId(id);
        k.setPublicKey(pair.publicKeyB64());
        return List.of(k);
    }

    /** The operational key set: what the roster snapshot is signed under. */
    private static List<ResolverProperties.TrustedKey> authorityKeys() {
        return keys("auth-a", AUTH);
    }

    /** The governance key set: what a policy bundle is signed under after Phase 2. */
    private static List<ResolverProperties.TrustedKey> governanceKeys() {
        return keys("gov-a", GOVERNANCE);
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

    private static RoutingPolicyBundle policySignedBy(String keyId, Ed25519.KeyPairB64 key,
                                                      boolean delegateSign) {
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setSigningKeyId(keyId);
        props.getPolicy().setSigningPrivateKey(key.privateKeyB64());
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
                ? RoutingPolicySigner.signZone(authoritySigned, "vivo-sp", "delegate-vivo",
                        DELEGATE.privateKeyB64())
                : authoritySigned;
    }

    private static RoutingPolicyBundle signedPolicy(boolean delegateSign) {
        return policySignedBy("gov-a", GOVERNANCE, delegateSign);
    }

    private static ResolverVerifier verifier() {
        return new ResolverVerifier(authorityKeys(), 1, governanceKeys(), 1);
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
    void rejectsAPolicySignedOnlyByTheOperationalAuthorityKey() {
        // The roster key is not a governance key. Before Phase 2 an empty policy key list fell back to the
        // authority keys and this bundle verified; now it does not, which is the point of the change.
        RoutingPolicyBundle signedByAuthority = policySignedBy("auth-a", AUTH, true);

        assertThatThrownBy(() -> verifier().verifyPolicy(signedByAuthority))
                .isInstanceOf(global.gua.resolver.policy.RoutingPolicyVerifier
                        .RoutingPolicyVerificationException.class);
    }

    @Test
    void withNoPolicyKeysNothingVerifiesRatherThanFallingBack() {
        ResolverVerifier noPolicyKeys = new ResolverVerifier(authorityKeys(), 1, List.of(), 1);

        assertThatThrownBy(() -> noPolicyKeys.verifyPolicy(signedPolicy(true)))
                .isInstanceOf(global.gua.resolver.policy.RoutingPolicyVerifier
                        .RoutingPolicyVerificationException.class);
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
        // wrong key, right id
        RoutingPolicyBundle badlySigned = policySignedBy("gov-a", stranger, false);

        assertThatThrownBy(() -> verifier().verifyPolicy(badlySigned))
                .isInstanceOf(global.gua.resolver.policy.RoutingPolicyVerifier
                        .RoutingPolicyVerificationException.class);
    }
}
