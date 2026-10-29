package global.gua.resolver.verify;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.policy.CanonicalRoutingPolicy;
import global.gua.resolver.policy.DelegationZone;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicyRule;
import global.gua.resolver.policy.RoutingPolicySigner;
import global.gua.resolver.policy.RoutingPolicyVerifier.RoutingPolicyVerificationException;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterForm;
import global.gua.resolver.roster.RosterSigner;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The reference client verifier verifies signed artifacts and independently reproduces the resolver's
 * new-account decision, so a client never has to trust the resolver's answer. The roster and policy trust
 * roots are deliberately different keys here, so a port that conflates them fails.
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

    /** The governance key set: what a policy bundle is signed under. */
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
        return policySignedBy(keyId, key, delegateSign, Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600));
    }

    private static RoutingPolicyBundle policySignedBy(String keyId, Ed25519.KeyPairB64 key, boolean delegateSign,
                                                      Instant notBefore, Instant expiresAt) {
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setSigningKeyId(keyId);
        props.getPolicy().setSigningPrivateKey(key.privateKeyB64());
        RoutingPolicyBundle unsigned = new RoutingPolicyBundle(
                RoutingPolicyBundle.SCHEMA_VERSION, "br-policy", 3, Instant.now(), notBefore, expiresAt,
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

    private static ResolverVerifier verifierAt(Instant now) {
        return new ResolverVerifier(authorityKeys(), 1, governanceKeys(), 1, Clock.fixed(now, ZoneOffset.UTC));
    }

    @Test
    void verifiesSignedArtifactsAndReproducesTheRegisterDecision() {
        SignedRoster roster = signedRoster();
        RoutingPolicyBundle policy = signedPolicy(true);
        ResolverVerifier verifier = verifier();

        verifier.verifyRoster(roster, RosterForm.V1);
        verifier.verifyPolicy(policy);

        var ctx = PlacementContext.forPhone("+5511987654321");   // matches +551198 -> carrier
        assertThat(verifier.reproduceNewAccountDecision(ctx, roster, RosterForm.V1, policy).homeserver().id())
                .isEqualTo("carrier");
    }

    @Test
    void aPolicyIsInEffectFromNotBeforeUntilJustBeforeExpiresAt() {
        Instant now = Instant.parse("2026-10-27T12:00:00Z");
        ResolverVerifier verifier = verifierAt(now);

        verifier.verifyPolicy(policySignedBy("gov-a", GOVERNANCE, true, now, now.plusMillis(1)));
        assertThatThrownBy(() -> verifier.verifyPolicy(
                policySignedBy("gov-a", GOVERNANCE, true, now.plusMillis(1), now.plusSeconds(60))))
                .isInstanceOf(RoutingPolicyVerificationException.class);
        assertThatThrownBy(() -> verifier.verifyPolicy(
                policySignedBy("gov-a", GOVERNANCE, true, now.minusSeconds(60), now)))
                .isInstanceOf(RoutingPolicyVerificationException.class);
    }

    @Test
    void placementRefusesAnExpiredPolicyInsteadOfApplyingIt() {
        Instant now = Instant.parse("2026-10-27T12:00:00Z");
        RoutingPolicyBundle expired = policySignedBy("gov-a", GOVERNANCE, true, now.minusSeconds(3600),
                now.minusSeconds(60));

        assertThatThrownBy(() -> verifierAt(now).reproduceNewAccountDecision(
                PlacementContext.forPhone("+5511987654321"), signedRoster(), RosterForm.V1, expired))
                .isInstanceOf(RoutingPolicyVerificationException.class);
    }

    @Test
    void signatureOutcomesNameWhySignaturesFallShort() {
        SignedRoster roster = signedRoster();
        assertThat(verifier().rosterSignatureOutcome(roster, RosterForm.V1)).isEqualTo("valid");
        assertThat(new ResolverVerifier(keys("auth-b", AUTH), 1, governanceKeys(), 1)
                .rosterSignatureOutcome(roster, RosterForm.V1)).isEqualTo("invalid(unknown_key_id)");
        assertThat(verifier().rosterSignatureOutcome(roster, RosterForm.LEGACY)).isEqualTo("invalid(bad_signature)");
        assertThat(new ResolverVerifier(authorityKeys(), 1, List.of(), 1).policySignatureOutcome(signedPolicy(true)))
                .isEqualTo("unverifiable(no_policy_keys)");
        SignedRoster unnamed = new SignedRoster(roster.version(), roster.issuedAt(), roster.entries(),
                roster.logCheckpoint(), List.of(new SignedRoster.AuthoritySignature(null, "AAAA")));
        assertThat(verifier().rosterSignatureOutcome(unnamed, RosterForm.V1)).isEqualTo("invalid(unknown_key_id)");
    }

    @Test
    void aPolicyLogStepNeedsTheBundleLoggedUnderTheCheckpoint() {
        RoutingPolicyBundle policy = signedPolicy(true);
        TransparencyLog.Event admit = event(0, "ADMIT", "carrier", MerkleTree.sha256Hex("admit"));
        TransparencyLog.Event publish = event(1, "POLICY_PUBLISH", "br-policy:v3",
                MerkleTree.sha256Hex(CanonicalRoutingPolicy.bytes(policy)));
        TransparencyLog.Event newer = event(2, "POLICY_PUBLISH", "br-policy:v4", MerkleTree.sha256Hex("v4"));
        List<TransparencyLog.Event> log = List.of(admit, publish, newer);

        assertThat(ResolverVerifier.policyLogOutcome(log, checkpoint(log, 2), policy)).isEqualTo("valid");
        assertThat(ResolverVerifier.policyLogOutcome(log, checkpoint(log, 1), policy))
                .isEqualTo("unverifiable(policy_newer_than_checkpoint)");
        assertThat(ResolverVerifier.policyLogOutcome(log, checkpoint(log, 3), policy))
                .isEqualTo("unverifiable(policy_superseded)");
        assertThat(ResolverVerifier.policyLogOutcome(log, checkpoint(log, 1), null)).isEqualTo("notPresent");
        assertThat(ResolverVerifier.policyLogOutcome(log, checkpoint(log, 2), null))
                .isEqualTo("unverifiable(policy_not_served)");
        assertThat(ResolverVerifier.policyLogOutcome(log, new SignedRoster.LogCheckpoint("00", 2), policy))
                .isEqualTo("invalid(log_mismatch)");
    }

    private static TransparencyLog.Event event(long index, String type, String subject, String payloadHash) {
        return new TransparencyLog.Event(index, type, subject, payloadHash, "2026-10-27T00:00:00Z");
    }

    private static SignedRoster.LogCheckpoint checkpoint(List<TransparencyLog.Event> log, int size) {
        return new SignedRoster.LogCheckpoint(
                MerkleTree.root(log.subList(0, size).stream().map(TransparencyLog.Event::leafHash).toList()), size);
    }

    @Test
    void rejectsAPolicySignedOnlyByTheOperationalAuthorityKey() {
        // The roster key is not a governance key: an empty policy key list does not fall back to the
        // authority keys.
        RoutingPolicyBundle signedByAuthority = policySignedBy("auth-a", AUTH, true);

        assertThatThrownBy(() -> verifier().verifyPolicy(signedByAuthority))
                .isInstanceOf(RoutingPolicyVerificationException.class);
    }

    @Test
    void withNoPolicyKeysNothingVerifiesRatherThanFallingBack() {
        ResolverVerifier noPolicyKeys = new ResolverVerifier(authorityKeys(), 1, List.of(), 1);

        assertThatThrownBy(() -> noPolicyKeys.verifyPolicy(signedPolicy(true)))
                .isInstanceOf(RoutingPolicyVerificationException.class);
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

        assertThatThrownBy(() -> verifier().verifyRoster(forged, RosterForm.V1))
                .isInstanceOf(global.gua.resolver.roster.RosterVerifier.RosterVerificationException.class);
    }

    @Test
    void rejectsAPolicyNotSignedByATrustedAuthority() {
        Ed25519.KeyPairB64 stranger = Ed25519.generate();
        // wrong key, right id
        RoutingPolicyBundle badlySigned = policySignedBy("gov-a", stranger, false);

        assertThatThrownBy(() -> verifier().verifyPolicy(badlySigned))
                .isInstanceOf(RoutingPolicyVerificationException.class);
    }
}
