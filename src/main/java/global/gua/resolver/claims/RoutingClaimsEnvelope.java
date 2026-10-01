package global.gua.resolver.claims;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** subject binds the envelope to one E.164 phone and is part of the signed bytes. */
public record RoutingClaimsEnvelope(
        String schemaVersion,
        String issuer,
        String audience,
        Instant issuedAt,
        Instant expiresAt,
        String nonce,
        String subject,
        List<String> affiliations,
        Map<String, String> attributes,
        List<ClaimSignature> signatures) {

    public static final String SCHEMA_VERSION = "gua-routing-claims.v1";

    public record ClaimSignature(String keyId, String signatureB64) {}
}
