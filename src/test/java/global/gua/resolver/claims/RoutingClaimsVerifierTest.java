package global.gua.resolver.claims;

import java.time.Instant;
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

    @Test
    void verifiesSignedRoutingClaimsAndMarksAttributesTrusted() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());

        RoutingClaimsVerifier.VerifiedRoutingClaims verified = verifier(kp.publicKeyB64())
                .verify(signed);

        assertThat(verified.affiliations()).containsExactly("students.usp.br");
        assertThat(verified.attributes()).containsEntry("email_domain", "usp.br");
        assertThat(verified.attributes()).containsEntry(RoutingClaimsVerifier.VERIFIED_ATTRIBUTE, "true");
        assertThat(verified.attributes()).containsEntry("routing_claims_issuer", "https://account.gua.test");
    }

    @Test
    void rejectsTamperedRoutingClaims() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());
        RoutingClaimsEnvelope tampered = new RoutingClaimsEnvelope(signed.schemaVersion(), signed.issuer(),
                signed.audience(), signed.issuedAt(), signed.expiresAt(), signed.nonce(),
                signed.affiliations(), Map.of("email_domain", "evil.example"), signed.signatures());

        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(tampered))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("signature");
    }

    @Test
    void rejectsExpiredRoutingClaims() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope expired = new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION,
                "https://account.gua.test", "gua-resolver", Instant.now().minusSeconds(600),
                Instant.now().minusSeconds(300), "nonce", List.of(), Map.of(), List.of());
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(expired, "claims-a", kp.privateKeyB64());

        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(signed))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void rejectsRoutingClaimsWithoutNonceWhenReplayProtectionIsEnabled() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope missingNonce = new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION,
                "https://account.gua.test", "gua-resolver", Instant.now().minusSeconds(10),
                Instant.now().plusSeconds(200), null, List.of(), Map.of(), List.of());
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(missingNonce, "claims-a", kp.privateKeyB64());

        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(signed))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("nonce is required");
    }

    @Test
    void rejectsClaimsWhoseLifetimeExceedsConfiguredMaximum() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope tooLong = new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION,
                "https://account.gua.test", "gua-resolver", Instant.now().minusSeconds(10),
                Instant.now().plusSeconds(600), "nonce", List.of(), Map.of(), List.of());
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(tooLong, "claims-a", kp.privateKeyB64());

        assertThatThrownBy(() -> verifier(kp.publicKeyB64()).verify(signed))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("lifetime");
    }

    @Test
    void rejectsReplayedNonceAfterSuccessfulVerification() {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        RoutingClaimsEnvelope signed = RoutingClaimsSigner.sign(unsigned(Map.of("email_domain", "usp.br")),
                "claims-a", kp.privateKeyB64());
        RoutingClaimsVerifier verifier = verifier(kp.publicKeyB64());

        verifier.verify(signed);

        assertThatThrownBy(() -> verifier.verify(signed))
                .isInstanceOf(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
                .hasMessageContaining("already used");
    }

    private static RoutingClaimsEnvelope unsigned(Map<String, String> attrs) {
        return new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION,
                "https://account.gua.test", "gua-resolver", Instant.now().minusSeconds(10),
                Instant.now().plusSeconds(200), "nonce", List.of("students.usp.br"), attrs, List.of());
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
