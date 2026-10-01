package global.gua.resolver.policy;

import java.time.Instant;
import java.util.List;

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

    public record PolicySignature(String authorityKeyId, String signatureB64) {}

    /** delegateKeyId must match the zone's delegateKeyId. */
    public record DelegateSignature(String zoneId, String delegateKeyId, String signatureB64) {}
}
