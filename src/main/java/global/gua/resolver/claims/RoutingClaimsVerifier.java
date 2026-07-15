package global.gua.resolver.claims;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

/** Verifies signed MAS / identity-service routing claims before policy rules can consume them. */
@Component
public class RoutingClaimsVerifier {

    private static final Logger log = LoggerFactory.getLogger(RoutingClaimsVerifier.class);

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

        // Trust root for routing-claims signatures. Prefer keys scoped to the claims issuer
        // (MAS/identity-service); fall back to policy, then authority keys, only as a bootstrap convenience.
        // The fallback silently widens WHO can mint institutional/OIDC claims, so warn loudly: production
        // should set an explicit gua.resolver.claims.trusted-keys list scoped to the identity-service issuer.
        String keySource = "claims";
        List<ResolverProperties.TrustedKey> keys = props.getClaims().getTrustedKeys();
        if (keys.isEmpty()) {
            keys = props.getPolicy().getTrustedKeys();
            keySource = "policy";
        }
        if (keys.isEmpty()) {
            keys = props.getAuthority().getTrustedKeys();
            keySource = "authority";
        }
        for (ResolverProperties.TrustedKey k : keys) {
            if (k.getId() != null && k.getPublicKey() != null && !k.getPublicKey().isBlank()) {
                trustedKeys.put(k.getId(), Ed25519.publicKey(k.getPublicKey()));
            }
        }
        if (!"claims".equals(keySource) && !trustedKeys.isEmpty()) {
            log.warn("Routing-claims signatures are verified against the {} trusted keys (no "
                    + "gua.resolver.claims.trusted-keys configured). In production, set an explicit claims "
                    + "trusted-keys list scoped to the identity-service issuer so the claims-issuer trust "
                    + "domain is not conflated with the {} trust domain.", keySource, keySource);
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
                Map.copyOf(attrs), true);
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
        // Reject malformed collections up front so canonicalization (which sorts affiliations and would NPE
        // on a null element) never runs on bad input: a crafted null entry becomes a clean 400, not a 500.
        if (envelope.affiliations() != null) {
            for (String affiliation : envelope.affiliations()) {
                if (blank(affiliation)) {
                    throw invalid("routing claims affiliation entry is null or blank");
                }
            }
        }
        if (envelope.attributes() != null) {
            for (Map.Entry<String, String> entry : envelope.attributes().entrySet()) {
                if (blank(entry.getKey()) || entry.getValue() == null) {
                    throw invalid("routing claims attribute entry has a null/blank key or null value");
                }
            }
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
        // Retain the nonce until the end of the ACCEPTANCE window (expiresAt + skew), not just expiresAt, so
        // an envelope still accepted during the skew grace period cannot be replayed after cleanup would
        // otherwise have purged its row.
        Duration skew = maxClockSkew == null ? Duration.ZERO : maxClockSkew;
        Instant retainUntil = envelope.expiresAt().plus(skew);
        if (!replayStore.recordIfNew(envelope.issuer(), envelope.nonce(), retainUntil)) {
            throw invalid("routing claims nonce was already used");
        }
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    private static InvalidRoutingClaimsException invalid(String message) {
        return new InvalidRoutingClaimsException(message);
    }

    /**
     * The trusted result of verification. {@code verified} is true only when a real envelope passed every
     * check; it is the non-forgeable signal the placement context keys off, so it is derived from the
     * verification outcome here rather than re-inferred from envelope presence at the call site.
     */
    public record VerifiedRoutingClaims(List<String> affiliations, Map<String, String> attributes,
                                        boolean verified) {
        static VerifiedRoutingClaims empty() {
            return new VerifiedRoutingClaims(List.of(), Map.of(), false);
        }
    }

    public static class InvalidRoutingClaimsException extends RuntimeException {
        public InvalidRoutingClaimsException(String message) {
            super(message);
        }
    }
}
