package global.gua.resolver.policy;

/**
 * One signed routing rule inside a policy bundle. Rules choose only among homeservers that are already in
 * the signed roster; they cannot admit homeservers by themselves.
 */
public record RoutingPolicyRule(
        String id,
        int priority,
        MatchType matchType,
        String matchValue,
        String oidcIssuer,
        String oidcClaim,
        String targetHomeserverId,
        String delegatedZoneId,
        String reason,
        AssignmentPolicy assignmentPolicy,
        Boolean enabled) {

    public enum MatchType {
        PHONE_PREFIX,
        INSTITUTION_DOMAIN,
        OIDC_CLAIM
    }

    public enum AssignmentPolicy {
        PORTABLE,
        REQUIRES_CONFIRMATION,
        LOCKED_BY_POLICY
    }

    public boolean isEnabled() {
        return enabled == null || enabled;
    }

    public AssignmentPolicy effectiveAssignmentPolicy() {
        return assignmentPolicy == null ? AssignmentPolicy.PORTABLE : assignmentPolicy;
    }
}
