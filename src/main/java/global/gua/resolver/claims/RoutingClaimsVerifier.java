package global.gua.resolver.claims;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

/** Verifies signed MAS / identity-service routing claims before policy rules can consume them. */
@Component
public class RoutingClaimsVerifier {

    public static final String VERIFIED_ATTRIBUTE = "gua_claims_verified";

    private final String audience;
    private final Duration maxClockSkew;
    private final Clock clock;
    private final Map<String, PublicKey> trustedKeys = new HashMap<>();

    @Autowired
    public RoutingClaimsVerifier(ResolverProperties props) {
        this(props, Clock.systemUTC());
    }

    RoutingClaimsVerifier(ResolverProperties props, Clock clock) {
        this.audience = props.getClaims().getAudience();
        this.maxClockSkew = props.getClaims().getMaxClockSkew();
        this.clock = clock;
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

    public VerifiedRoutingClaims verify(RoutingClaimsEnvelope envelope) {
        if (envelope == null) {
            return VerifiedRoutingClaims.empty();
        }
        validateEnvelope(envelope);
        requireValidSignature(envelope);
        Map<String, String> attrs = new HashMap<>(envelope.attributes() == null ? Map.of() : envelope.attributes());
        attrs.put(VERIFIED_ATTRIBUTE, "true");
        attrs.putIfAbsent("routing_claims_issuer", envelope.issuer());
        return new VerifiedRoutingClaims(
                envelope.affiliations() == null ? List.of() : List.copyOf(envelope.affiliations()),
                Map.copyOf(attrs));
    }

    private void validateEnvelope(RoutingClaimsEnvelope envelope) {
        if (!RoutingClaimsEnvelope.SCHEMA_VERSION.equals(envelope.schemaVersion())) {
            throw invalid("unsupported routing claims schema");
        }
        if (blank(envelope.issuer())) {
            throw invalid("routing claims issuer is required");
        }
        if (!audience.equals(envelope.audience())) {
            throw invalid("routing claims audience mismatch");
        }
        Instant now = Instant.now(clock);
        Duration skew = maxClockSkew == null ? Duration.ZERO : maxClockSkew;
        if (envelope.issuedAt() == null || envelope.issuedAt().isAfter(now.plus(skew))) {
            throw invalid("routing claims issuedAt is invalid");
        }
        if (envelope.expiresAt() == null || !envelope.expiresAt().isAfter(now.minus(skew))) {
            throw invalid("routing claims expired");
        }
    }

    private void requireValidSignature(RoutingClaimsEnvelope envelope) {
        byte[] canonical = CanonicalRoutingClaims.bytes(envelope);
        Set<String> counted = new HashSet<>();
        for (RoutingClaimsEnvelope.ClaimSignature sig :
                envelope.signatures() == null ? List.<RoutingClaimsEnvelope.ClaimSignature>of()
                        : envelope.signatures()) {
            PublicKey key = trustedKeys.get(sig.keyId());
            if (key == null || counted.contains(sig.keyId())) {
                continue;
            }
            if (Ed25519.verify(key, canonical, sig.signatureB64())) {
                return;
            }
            counted.add(sig.keyId());
        }
        throw invalid("routing claims signature is invalid");
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
