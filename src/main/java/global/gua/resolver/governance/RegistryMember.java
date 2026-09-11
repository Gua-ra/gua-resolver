package global.gua.resolver.governance;

import java.util.List;

import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.roster.RosterEntry;

/**
 * One homeserver as the governance keys admit it: its status, the placement attributes the authority used to
 * hold alone, and the hash of the member's own self-signed entry.
 *
 * <p>{@code memberEntryHash} is what keeps governance from redefining a member. The epoch signs the hash of
 * the entry the member signed, not the member's fields, so governance can admit that exact entry, suspend it
 * or revoke it, and can do nothing else to it (ADM-001 L10: "governance able only to admit or revoke"). It
 * is absent for an entry that has not been attested yet, which is the honest encoding of "governance is
 * admitting a member whose own signature is not yet on file".
 *
 * @param homeserverId    the federation id
 * @param status          ACTIVE, SUSPENDED or REVOKED; PENDING is an intent, never a governed status
 * @param memberEntryHash SHA-256 hex of the member's {@code gua-member-entry.v1} bytes, or null
 * @param weight          load-spreading weight for placement
 * @param acceptsNew      whether this homeserver receives new account placement
 * @param claims          the declarative placement claims this operator is authorised to assert
 */
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
    }
}
