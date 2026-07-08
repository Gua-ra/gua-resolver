package global.gua.resolver.claims;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

/** Verifies signed MAS / identity-service routing claims before policy rules can consume them. */
@Component
public class RoutingClaimsVerifier {

    private final String audience;
    private final Duration maxClockSkew;
    private final Duration maxLifetime;
    private final boolean replayProtectionEnabled;
    private final boolean requireSubjectBinding;
    private final Clock clock;
    private final RoutingClaimsReplayStore replayStore;
    private final Map<String, PublicKey> trustedKeys = new HashMap<>();

    @Autowired
    public RoutingClaimsVerifier(ResolverProperties props, RoutingClaimsReplayStore replayStore) {
        this(props, Clock.systemUTC(), replayStore);
    }

    RoutingClaimsVerifier(ResolverProperties props, Clock clock, RoutingClaimsReplayStore replayStore) {
        this.audience = props.getClaims().getAudience();
        this.maxClockSkew = props.getClaims().getMaxClockSkew();
        this.maxLifetime = props.getClaims().getMaxLifetime();
        this.replayProtectionEnabled = props.getClaims().isReplayProtectionEnabled();
        this.requireSubjectBinding = props.getClaims().isRequireSubjectBinding();
        this.clock = clock;
        this.replayStore = replayStore;
        List<ResolverProperties.TrustedKey> keys = !props.getClaims().getTrustedKeys().isEmpty()
                ? props.getClaims().getTrustedKeys()
                : (!props.getPolicy().getTrustedKeys().isEmpty()
                        ? props.getPolicy().getTrustedKeys()
                        : props.getAuthority().getTrustedKeys());
        for (ResolverProperties.TrustedKey k : keys) {
            if (k.getId() != null && k.getPublicKey() != null && !k.getPublicKey().isBlank()) {
                trustedKeys.put(k.getId(), Ed25519.publicKey(k.getPublicKey()));
            }
        }
    }

    /**
     * Verify the envelope and return the trusted affiliations/attributes.
     *
     * @param envelope        the transported (signed) envelope, or {@code null} if the caller sent none
     * @param expectedSubject the E.164 phone the request is for; the envelope's {@code subject}, when present
     *                        (and always when subject binding is required), must equal this
     */
    public VerifiedRoutingClaims verify(RoutingClaimsEnvelope envelope, String expectedSubject) {
        if (envelope == null) {
            return VerifiedRoutingClaims.empty();
        }
        validateEnvelope(envelope, expectedSubject);
        requireValidSignature(envelope);
        recordNonce(envelope);
        // Only the raw asserted affiliations/attributes are returned; the "verified" signal is carried by
        // PlacementContext.claimsVerified (a non-forgeable flag), never by a magic attribute a caller could set.
        Map<String, String> attrs = new HashMap<>();
        if (envelope.attributes() != null) {
            envelope.attributes().forEach((k, v) -> {
                if (k != null && v != null) {
                    attrs.put(k, v);
                }
            });
        }
        return new VerifiedRoutingClaims(
                envelope.affiliations() == null ? List.of() : List.copyOf(envelope.affiliations()),
                Map.copyOf(attrs));
    }

    private void validateEnvelope(RoutingClaimsEnvelope envelope, String expectedSubject) {
        if (!RoutingClaimsEnvelope.SCHEMA_VERSION.equals(envelope.schemaVersion())) {
            throw invalid("unsupported routing claims schema");
        }
        if (blank(envelope.issuer())) {
            throw invalid("routing claims issuer is required");
        }
        if (!audience.equals(envelope.audience())) {
            throw invalid("routing claims audience mismatch");
        }
        if (requireSubjectBinding && blank(envelope.subject())) {
            throw invalid("routing claims subject is required");
        }
        if (!blank(envelope.subject()) && !envelope.subject().equals(expectedSubject)) {
            throw invalid("routing claims subject does not match the request");
        }
        Instant now = Instant.now(clock);
        Duration skew = maxClockSkew == null ? Duration.ZERO : maxClockSkew;
        if (envelope.issuedAt() == null || envelope.issuedAt().isAfter(now.plus(skew))) {
            throw invalid("routing claims issuedAt is invalid");
        }
        if (envelope.expiresAt() == null || !envelope.expiresAt().isAfter(now.minus(skew))) {
            throw invalid("routing claims expired");
        }
        if (envelope.expiresAt().isBefore(envelope.issuedAt())) {
            throw invalid("routing claims expiresAt precedes issuedAt");
        }
        Duration lifetime = maxLifetime == null ? Duration.ZERO : maxLifetime;
        if (!lifetime.isZero() && envelope.expiresAt().isAfter(envelope.issuedAt().plus(lifetime))) {
            throw invalid("routing claims lifetime exceeds maximum");
        }
        if (replayProtectionEnabled && blank(envelope.nonce())) {
            throw invalid("routing claims nonce is required");
        }
    }

    private void requireValidSignature(RoutingClaimsEnvelope envelope) {
        byte[] canonical = CanonicalRoutingClaims.bytes(envelope);
        List<RoutingClaimsEnvelope.ClaimSignature> signatures = envelope.signatures() == null
                ? List.of() : envelope.signatures();
        for (RoutingClaimsEnvelope.ClaimSignature sig : signatures) {
            if (sig == null) {
                continue;
            }
            PublicKey key = trustedKeys.get(sig.keyId());
            if (key != null && Ed25519.verify(key, canonical, sig.signatureB64())) {
                return;
            }
        }
        throw invalid("routing claims signature is invalid");
    }

    private void recordNonce(RoutingClaimsEnvelope envelope) {
        if (!replayProtectionEnabled) {
            return;
        }
        if (!replayStore.recordIfNew(envelope.issuer(), envelope.nonce(), envelope.expiresAt())) {
            throw invalid("routing claims nonce was already used");
        }
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    private static InvalidRoutingClaimsException invalid(String message) {
        return new InvalidRoutingClaimsException(message);
    }

    public record VerifiedRoutingClaims(List<String> affiliations, Map<String, String> attributes) {
        static VerifiedRoutingClaims empty() {
            return new VerifiedRoutingClaims(List.of(), Map.of());
        }
    }

    public static class InvalidRoutingClaimsException extends RuntimeException {
        public InvalidRoutingClaimsException(String message) {
            super(message);
        }
    }
}
