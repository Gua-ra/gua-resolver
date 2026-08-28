package global.gua.resolver.policy;

import java.time.Instant;
import java.util.List;

/**
 * Versioned, signed routing policy artifact. It is intentionally transport-neutral: a file, HTTP mirror,
 * object store, or future DB row can distribute the same canonical bytes and signatures.
 */
public record RoutingPolicyBundle(
        String schemaVersion,
        String policyId,
        long version,
        Instant issuedAt,
        Instant notBefore,
        Instant expiresAt,
        List<DelegationZone> delegationZones,
        List<RoutingPolicyRule> rules,
        FallbackStrategy fallback,
        List<PolicySignature> signatures,
        List<DelegateSignature> delegateSignatures) {

    public static final String SCHEMA_VERSION = "gua-routing-policy.v1";

    public record FallbackStrategy(String type, boolean enabled) {}

    /** Authority (governance) signature over the whole canonical bundle: threshold k-of-n. */
    public record PolicySignature(String authorityKeyId, String signatureB64) {}

    /**
     * A delegate's signature over the rules inside one delegation zone (see
     * {@code CanonicalDelegatedRules}). {@code delegateKeyId} must match the zone's {@code delegateKeyId}.
     */
    public record DelegateSignature(String zoneId, String delegateKeyId, String signatureB64) {}
}
