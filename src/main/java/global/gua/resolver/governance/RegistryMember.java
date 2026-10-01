package global.gua.resolver.governance;

import java.util.List;

import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.roster.RosterEntry;

/** memberEntryHash is the hash of the member's own signed entry, or null before it has attested. */
public record RegistryMember(
        String homeserverId,
        RosterEntry.Status status,
        String memberEntryHash,
        long weight,
        boolean acceptsNew,
        List<ClaimPredicate> claims) {

    public RegistryMember {
        claims = claims == null ? List.of() : List.copyOf(claims);
    }

    public void validateShape() {
        if (homeserverId == null || homeserverId.isBlank()) {
            throw new GovernanceException("homeserverId is required");
        }
        if (status == null || status == RosterEntry.Status.PENDING) {
            throw new GovernanceException(
                    "a governed member status is ACTIVE, SUSPENDED or REVOKED, not " + status);
        }
        if (weight < 0) {
            throw new GovernanceException("weight must not be negative");
        }
        if (weight > Integer.MAX_VALUE) {
            throw new GovernanceException("weight " + weight + " exceeds the largest weight the roster can "
                    + "hold (" + Integer.MAX_VALUE + ")");
        }
    }
}
