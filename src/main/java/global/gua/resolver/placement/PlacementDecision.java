package global.gua.resolver.placement;

import global.gua.resolver.domain.Homeserver;

/**
 * Auditable placement result. API callers normally need only {@link #homeserver()}, but operators need the
 * rule, policy, and delegation identifiers to reproduce and audit why a placement happened.
 */
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
