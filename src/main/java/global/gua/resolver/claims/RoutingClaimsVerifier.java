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

        // With governance required only claims issuer keys verify; otherwise policy keys, then authority
        // keys.
        boolean governanceRequired = props.getGovernance().isRequired();
        String keySource = "claims";
        List<ResolverProperties.TrustedKey> keys = props.getClaims().getTrustedKeys();
        if (!governanceRequired && keys.isEmpty()) {
            keys = props.getPolicy().getTrustedKeys();
            keySource = "policy";
        }
        if (!governanceRequired && keys.isEmpty()) {
            keys = props.getAuthority().getTrustedKeys();
            keySource = "authority";
        }
        for (ResolverProperties.TrustedKey k : keys) {
            if (k.getId() != null && k.getPublicKey() != null && !k.getPublicKey().isBlank()) {
                trustedKeys.put(k.getId(), Ed25519.publicKey(k.getPublicKey()));
            }
        }
        if (trustedKeys.isEmpty()) {
            log.warn("No routing-claims trust root: every signed routing-claims envelope will be rejected, "
                    + "so no institution or OIDC placement rule can match. With governance required ({}) "
                    + "that is the intended fail-closed state (ADM-001 L8) while nothing issues envelopes; "
                    + "a claims issuer ships its public key into gua.resolver.claims.trusted-keys first.",
                    governanceRequired);
        } else if (!"claims".equals(keySource)) {
            log.warn("Routing-claims signatures are verified against the {} trusted keys (no "
                    + "gua.resolver.claims.trusted-keys configured, and governance is not required yet). "
                    + "That conflates the claims-issuer trust domain with the {} one: set an explicit claims "
                    + "trusted-keys list scoped to the issuer before the governance cutover, because with "
                    + "gua.resolver.governance.required on this fallback is gone and every envelope is "
                    + "rejected (ADM-001 L8).", keySource, keySource);
        }
    }

    public VerifiedRoutingClaims verify(RoutingClaimsEnvelope envelope, String expectedSubject) {
        if (envelope == null) {
            return VerifiedRoutingClaims.empty();
        }
        validateEnvelope(envelope, expectedSubject);
        requireValidSignature(envelope);
        recordNonce(envelope);
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
        // Retain the nonce until expiresAt plus skew, the end of the acceptance window.
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
