package global.gua.resolver.claims;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoutingClaimsVerifierTest {

    private static final String SUBJECT = "+5511987654321";

    @Test
    void verifiesSignedRoutingClaimsAndReturnsAssertedAttributes() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());

        RoutingClaimsVerifier.VerifiedRoutingClaims verified = verifier(kp.publicKeyB64())
                .verify(signed, SUBJECT);

        assertThat(verified.affiliations()).containsExactly("students.usp.br");
        assertThat(verified.attributes()).containsEntry("email_domain", "usp.br");
    }

    @Test
    void rejectsTamperedRoutingClaims() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());
        RoutingClaimsEnvelope tampered = new RoutingClaimsEnvelope(signed.schemaVersion(), signed.issuer(),
                signed.audience(), signed.issuedAt(), signed.expiresAt(), signed.nonce(), signed.subject(),
                signed.affiliations(), Map.of("email_domain", "evil.example"), signed.signatures());

        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(tampered, SUBJECT))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("signature");
    }

    @Test
    void rejectsEnvelopeBoundToADifferentSubject() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());

        // A valid envelope issued for SUBJECT must not be usable against a different phone.
        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(signed, "+15555550100"))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("subject does not match");
    }

    @Test
    void rejectsEnvelopeWithoutSubjectWhenBindingRequired() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope noSubject = new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION,
                "https://account.gua.test", "gua-resolver", Instant.now().minusSeconds(10),
                Instant.now().plusSeconds(200), "nonce", null, List.of(), Map.of(), List.of());
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(noSubject, "claims-a", kp.privateKeyB64());

        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(signed, SUBJECT))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("subject is required");
    }

    @Test
    void acceptsWhenAValidSignatureFollowsABadSignatureForTheSameKeyId() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());
        // Prepend a bogus signature for the SAME keyId; the verifier must still find the valid one.
        List<RoutingClaimsEnvelope.ClaimSignature> sigs = new ArrayList<>();
        sigs.add(new RoutingClaimsEnvelope.ClaimSignature("claims-a", "AAAA"));
        sigs.addAll(signed.signatures());
        RoutingClaimsEnvelope reordered = new RoutingClaimsEnvelope(signed.schemaVersion(), signed.issuer(),
                signed.audience(), signed.issuedAt(), signed.expiresAt(), signed.nonce(), signed.subject(),
                signed.affiliations(), signed.attributes(), sigs);

        RoutingClaimsVerifier.VerifiedRoutingClaims verified = verifier(kp.publicKeyB64())
                .verify(reordered, SUBJECT);

        assertThat(verified.attributes()).containsEntry("email_domain", "usp.br");
    }

    @Test
    void aNullSignatureValueIsRejectedAsInvalidNotAsServerError() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope env = new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION,
                "https://account.gua.test", "gua-resolver", Instant.now().minusSeconds(10),
                Instant.now().plusSeconds(200), "nonce", SUBJECT, List.of(), Map.of(),
                List.of(new RoutingClaimsEnvelope.ClaimSignature("claims-a", null)));

        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(env, SUBJECT))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("signature");
    }

    @Test
    void aNullSignatureEntryDoesNotBlockALaterValidSignature() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());
        List<RoutingClaimsEnvelope.ClaimSignature> sigs = new ArrayList<>();
        sigs.add(null);   // a JSON null array element in "signatures"
        sigs.addAll(signed.signatures());
        RoutingClaimsEnvelope withNullEntry = new RoutingClaimsEnvelope(signed.schemaVersion(), signed.issuer(),
                signed.audience(), signed.issuedAt(), signed.expiresAt(), signed.nonce(), signed.subject(),
                signed.affiliations(), signed.attributes(), sigs);

        assertThat(verifier(kp.publicKeyB64()).verify(withNullEntry, SUBJECT).attributes())
                .containsEntry("email_domain", "usp.br");
    }

    @Test
    void rejectsExpiredRoutingClaims() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope expired = new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION,
                "https://account.gua.test", "gua-resolver", Instant.now().minusSeconds(600),
                Instant.now().minusSeconds(300), "nonce", SUBJECT, List.of(), Map.of(), List.of());
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(expired, "claims-a", kp.privateKeyB64());

        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(signed, SUBJECT))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void rejectsRoutingClaimsWithoutNonceWhenReplayProtectionIsEnabled() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope missingNonce = new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION,
                "https://account.gua.test", "gua-resolver", Instant.now().minusSeconds(10),
                Instant.now().plusSeconds(200), null, SUBJECT, List.of(), Map.of(), List.of());
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(missingNonce, "claims-a", kp.privateKeyB64());

        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(signed, SUBJECT))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("nonce is required");
    }

    @Test
    void rejectsClaimsWhoseLifetimeExceedsConfiguredMaximum() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope tooLong = new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION,
                "https://account.gua.test", "gua-resolver", Instant.now().minusSeconds(10),
                Instant.now().plusSeconds(600), "nonce", SUBJECT, List.of(), Map.of(), List.of());
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(tooLong, "claims-a", kp.privateKeyB64());

        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(signed, SUBJECT))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("lifetime");
    }

    @Test
    void rejectsReplayedNonceAfterSuccessfulVerification() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());
        RoutingClaimsVerifier verifier = verifier(kp.publicKeyB64());

        verifier.verify(signed, SUBJECT);

        assertThatThrownBy(() -> verifier.verify(signed, SUBJECT))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("already used");
    }

    private static RoutingClaimsEnvelope unsigned(Map<String, String> attrs) {
        return new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION,
                "https://account.gua.test", "gua-resolver", Instant.now().minusSeconds(10),
                Instant.now().plusSeconds(200), "nonce", SUBJECT, List.of("students.usp.br"), attrs, List.of());
    }

    private static ResolverProperties props(String publicKey) {
        ResolverProperties props = new ResolverProperties();
        ResolverProperties.TrustedKey trusted = new ResolverProperties.TrustedKey();
        trusted.setId("claims-a");
        trusted.setPublicKey(publicKey);
        props.getClaims().setTrustedKeys(List.of(trusted));
        return props;
    }

    private static RoutingClaimsVerifier verifier(String publicKey) {
        return new RoutingClaimsVerifier(props(publicKey), inMemoryReplayStore());
    }

    private static RoutingClaimsReplayStore inMemoryReplayStore() {
        return new RoutingClaimsReplayStore() {
            private final Set<String> seen = new HashSet<>();

            @Override
            public boolean recordIfNew(String issuer, String nonce, Instant expiresAt) {
                return seen.add(issuer + "\n" + nonce);
            }

            @Override
            public void removeExpired(Instant now) {
            }
        };
    }
}
