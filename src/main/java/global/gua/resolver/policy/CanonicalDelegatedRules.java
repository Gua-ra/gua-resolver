package global.gua.resolver.policy;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Deterministic bytes a delegate signs to authorise the rules inside one delegation zone. Binding policyId +
 * version + zoneId prevents a delegate signature from being lifted onto a different policy/version/zone. The
 * per-rule encoding is shared with {@link CanonicalRoutingPolicy#ruleLine} so the authority-signed bundle and
 * the delegate-signed rule set never disagree on what a rule is.
 */
public final class CanonicalDelegatedRules {

    private CanonicalDelegatedRules() {}

    /** {@code rulesInZone} may be the full bundle rule list; only rules whose delegatedZoneId == zoneId count. */
    public static byte[] bytes(String policyId, long version, String zoneId, List<RoutingPolicyRule> rulesInZone) {
        StringBuilder sb = new StringBuilder();
        sb.append("gua-delegated-rules.v1\n");
        sb.append("policyId=").append(nz(policyId)).append('\n');
        sb.append("version=").append(version).append('\n');
        sb.append("zoneId=").append(nz(zoneId)).append('\n');
        CanonicalRoutingPolicy.sortedRules(rulesInZone).stream()
                .filter(r -> zoneId != null && zoneId.equals(r.delegatedZoneId()))
                .forEach(r -> sb.append(CanonicalRoutingPolicy.ruleLine(r)).append('\n'));
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
