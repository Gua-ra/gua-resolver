package global.gua.resolver.placement;

import global.gua.resolver.domain.Homeserver;

public record PlacementDecision(
        Homeserver homeserver,
        String rule,
        String ruleId,
        String reason,
        String policyId,
        Long policyVersion,
        String delegatedZoneId,
        String assignmentPolicy) {

    public static PlacementDecision of(Homeserver homeserver, String rule, String ruleId, String reason) {
        return new PlacementDecision(homeserver, rule, ruleId, reason, null, null, null, null);
    }
}
