package global.gua.resolver.roster;

import java.time.Instant;
import java.util.List;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.ClaimPredicate;

/**
 * One admitted homeserver in the federation roster: the homeserver itself, the claim predicates it is
 * authorised to assert for placement, and the admission/lifecycle metadata. The authority validates that
 * no two entries' claim predicates overlap before admitting/updating.
 *
 * @param homeserver  the advertised homeserver
 * @param claims      declarative placement claims this operator is authorised to assert (may be empty)
 * @param admittedAt  when the authority admitted this homeserver
 * @param status      ACTIVE | SUSPENDED | REVOKED
 */
public record RosterEntry(
        Homeserver homeserver,
        List<ClaimPredicate> claims,
        Instant admittedAt,
        Status status) {

    public enum Status { ACTIVE, SUSPENDED, REVOKED }

    public boolean isActive() {
        return status == Status.ACTIVE;
    }
}
