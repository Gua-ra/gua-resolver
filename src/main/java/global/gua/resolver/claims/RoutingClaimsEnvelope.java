package global.gua.resolver.claims;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Signed claims from MAS / identity-service used for routing decisions. Public clients may transport this
 * envelope, but resolver policy treats institution/OIDC attributes as trusted only after signature,
 * audience, and expiry verification.
 */
public record RoutingClaimsEnvelope(
        String schemaVersion,
        String issuer,
        String audience,
        Instant issuedAt,
        Instant expiresAt,
        String nonce,
        List<String> affiliations,
        Map<String, String> attributes,
        List<ClaimSignature> signatures) {

    public static final String SCHEMA_VERSION = "gua-routing-claims.v1";

    public record ClaimSignature(String keyId, String signatureB64) {}
}
