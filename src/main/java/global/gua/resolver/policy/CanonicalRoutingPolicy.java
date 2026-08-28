package global.gua.resolver.policy;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.StringJoiner;

/**
 * Deterministic bytes for routing-policy signatures. Signatures themselves are excluded, so mirrors and
 * clients can reconstruct exactly what authorities signed.
 */
public final class CanonicalRoutingPolicy {

    private CanonicalRoutingPolicy() {}

    public static byte[] bytes(RoutingPolicyBundle bundle) {
        StringBuilder sb = new StringBuilder();
        sb.append("gua-routing-policy.v1\n");
        sb.append("schema=").append(nz(bundle.schemaVersion())).append('\n');
        sb.append("policyId=").append(nz(bundle.policyId())).append('\n');
        sb.append("version=").append(bundle.version()).append('\n');
        sb.append("issuedAt=").append(epoch(bundle.issuedAt())).append('\n');
        sb.append("notBefore=").append(epoch(bundle.notBefore())).append('\n');
        sb.append("expiresAt=").append(epoch(bundle.expiresAt())).append('\n');
        zones(bundle.delegationZones()).forEach(z -> sb.append(zone(z)).append('\n'));
        sortedRules(bundle.rules()).forEach(r -> sb.append(ruleLine(r)).append('\n'));
        RoutingPolicyBundle.FallbackStrategy f = bundle.fallback();
        sb.append("fallback=")
                .append(f == null ? "" : nz(f.type()) + ":" + f.enabled())
                .append('\n');
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static List<DelegationZone> zones(List<DelegationZone> zones) {
        return zones == null ? List.of() : zones.stream()
                .sorted(Comparator.comparing(DelegationZone::id, Comparator.nullsLast(String::compareTo)))
                .toList();
    }

    /** Deterministic rule order (priority, then id), shared with the per-zone delegate canonical form. */
    static List<RoutingPolicyRule> sortedRules(List<RoutingPolicyRule> rules) {
        return rules == null ? List.of() : rules.stream()
                .sorted(Comparator.comparingInt(RoutingPolicyRule::priority)
                        .thenComparing(RoutingPolicyRule::id, Comparator.nullsLast(String::compareTo)))
                .toList();
    }

    private static String zone(DelegationZone z) {
        StringJoiner j = new StringJoiner("\u001f");
        j.add("zone");
        j.add(nz(z.id()));
        j.add(z.scopeType() == null ? "" : z.scopeType().name());
        j.add(nz(z.scopeValue()));
        j.add(nz(z.delegatedAuthority()));
        j.add(nz(z.delegateKeyId()));
        j.add(nz(z.delegatePublicKey()));
        j.add(z.allowedHomeserverIds() == null ? ""
                : z.allowedHomeserverIds().stream().sorted().reduce((a, b) -> a + "|" + b).orElse(""));
        j.add(Long.toString(epoch(z.notBefore())));
        j.add(Long.toString(epoch(z.expiresAt())));
        return j.toString();
    }

    static String ruleLine(RoutingPolicyRule r) {
        StringJoiner j = new StringJoiner("\u001f");
        j.add("rule");
        j.add(nz(r.id()));
        j.add(Integer.toString(r.priority()));
        j.add(r.matchType() == null ? "" : r.matchType().name());
        j.add(nz(r.matchValue()));
        j.add(nz(r.oidcIssuer()));
        j.add(nz(r.oidcClaim()));
        j.add(nz(r.targetHomeserverId()));
        j.add(nz(r.delegatedZoneId()));
        j.add(nz(r.reason()));
        j.add(r.effectiveAssignmentPolicy().name());
        j.add(Boolean.toString(r.isEnabled()));
        return j.toString();
    }

    private static long epoch(Instant instant) {
        return instant == null ? 0L : instant.toEpochMilli();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
