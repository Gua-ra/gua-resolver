package global.gua.resolver.claims;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
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

    @Test
    void aNullAffiliationEntryIsRejectedAsInvalidNotAsServerError() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        // A crafted null element in "affiliations" must be a clean 400 (invalid), never a 500 from an NPE
        // while canonicalizing/sorting the list. Arrays.asList (unlike List.of) permits a null element.
        RoutingClaimsEnvelope withNullAffiliation = new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION,
                "https://account.gua.test", "gua-resolver", Instant.now().minusSeconds(10),
                Instant.now().plusSeconds(200), "nonce", SUBJECT, Arrays.asList("students.usp.br", null),
                Map.of(), List.of());

        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(withNullAffiliation, SUBJECT))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("affiliation");
    }

    @Test
    void retainsTheReplayNonceThroughTheAcceptanceWindowNotJustExpiry() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());
        Instant[] retainedUntil = new Instant[1];
        RoutingClaimsReplayStore capturing = new RoutingClaimsReplayStore() {
            @Override
            public boolean recordIfNew(String issuer, String nonce, Instant expiresAt) {
                retainedUntil[0] = expiresAt;
                return true;
            }

            @Override
            public void removeExpired(Instant now) {
            }
        };
        ResolverProperties props = props(kp.publicKeyB64());
        new RoutingClaimsVerifier(props, capturing).verify(signed, SUBJECT);

        // The nonce must be retained until expiresAt + clock skew, so an envelope still accepted during the
        // skew grace window cannot be replayed after a naive expiresAt-only cleanup would have purged it.
        assertThat(retainedUntil[0]).isEqualTo(signed.expiresAt().plus(props.getClaims().getMaxClockSkew()));
    }

    /** claims.trusted-keys empty, with the signing key present in BOTH of the fallback key sets. */
    private static ResolverProperties propsWithOnlyFallbackKeys(Ed25519.KeyPairB64 kp) {
        ResolverProperties props = new ResolverProperties();
        ResolverProperties.TrustedKey trusted = new ResolverProperties.TrustedKey();
        trusted.setId("claims-a");
        trusted.setPublicKey(kp.publicKeyB64());
        props.getPolicy().setTrustedKeys(List.of(trusted));
        props.getAuthority().setTrustedKeys(List.of(trusted));
        return props;
    }

    @Test
    void withGovernanceRequiredAndNoClaimsTrustedKeysEveryEnvelopeIsRejectedRatherThanFallingBack() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());

        // The policy AND authority key sets both contain the very key that signed this envelope. Falling back
        // to them is what let the roster-signing key mint institutional placement claims. ADM-001 L8: no
        // fallback, ever, once governance is required.
        ResolverProperties props = propsWithOnlyFallbackKeys(kp);
        props.getGovernance().setRequired(true);

        RoutingClaimsVerifier verifier = new RoutingClaimsVerifier(props, inMemoryReplayStore());

        assertThatThrownBy(() -> verifier.verify(signed, SUBJECT))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("signature is invalid");
    }

    @Test
    void withGovernanceNotRequiredTheClaimsTrustRootStillFallsBackToTheOperationalKeys() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());

        // The same configuration with the flag off: the pre-cutover chain is preserved deliberately. An
        // environment that has not run the key ceremony keeps whatever claims behaviour it has today, and the
        // narrowing happens when the operator flips the flag, not when this code is deployed. If this test
        // ever has to change, the cutover has stopped being a flag flip.
        RoutingClaimsVerifier verifier =
                new RoutingClaimsVerifier(propsWithOnlyFallbackKeys(kp), inMemoryReplayStore());

        assertThat(verifier.verify(signed, SUBJECT).attributes())
                .containsEntry("email_domain", "usp.br");
    }

    @Test
    void anAbsentEnvelopeIsStillSimplyUnverifiedClaims() {
        // Fail-closed applies to a presented envelope. A request that carries none is not an error; it just
        // gets no verified claims, so institution and OIDC rules cannot match.
        RoutingClaimsVerifier.VerifiedRoutingClaims claims =
                new RoutingClaimsVerifier(new ResolverProperties(), inMemoryReplayStore())
                        .verify(null, SUBJECT);

        assertThat(claims.verified()).isFalse();
        assertThat(claims.affiliations()).isEmpty();
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
