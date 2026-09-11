package global.gua.resolver.roster;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.ClaimPredicate;

/**
 * One admitted homeserver in the federation roster: the homeserver itself, the claim predicates it is
 * authorised to assert for placement, and the admission/lifecycle metadata. The authority validates that
 * no two entries' claim predicates overlap before admitting/updating.
 *
 * <p>An entry also carries the member's own signature over the fields it controls ({@link MemberAttestation},
 * ADM-007) once that member has attested. It is null for an entry admitted before Phase 1 or through the
 * legacy path, which {@link MemberEntryVerifier} reports as unattested rather than invalid, and it is omitted
 * from the JSON when null, so a roster of unattested entries is byte-identical to what clients see today.
 *
 * @param homeserver  the advertised homeserver
 * @param claims      declarative placement claims this operator is authorised to assert (may be empty)
 * @param admittedAt  when the authority admitted this homeserver
 * @param status      ACTIVE | SUSPENDED | REVOKED
 * @param member      the member's self-signature over its own endpoint and key fields, or null
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RosterEntry(
        Homeserver homeserver,
        List<ClaimPredicate> claims,
        Instant admittedAt,
        Status status,
        @JsonInclude(JsonInclude.Include.NON_NULL) MemberAttestation member) {

    /**
     * ACTIVE, SUSPENDED and REVOKED are governed statuses: with
     * {@code gua.resolver.governance.required} on, only a governance-signed membership epoch sets one
     * (ADM-001 L10). PENDING is not a governed status but an intent: an entry admitted while governance is
     * required waits in PENDING, is never served, and becomes ACTIVE only when an epoch says so.
     */
    public enum Status { ACTIVE, SUSPENDED, REVOKED, PENDING }

    /** An entry with no member attestation (seeded, legacy, or admitted before Phase 1). */
    public RosterEntry(Homeserver homeserver, List<ClaimPredicate> claims, Instant admittedAt, Status status) {
        this(homeserver, claims, admittedAt, status, null);
    }

    /** The same entry carrying {@code attestation}. */
    public RosterEntry withMember(MemberAttestation attestation) {
        return new RosterEntry(homeserver, claims, admittedAt, status, attestation);
    }

    @JsonIgnore
    public boolean isActive() {
        return status == Status.ACTIVE;
    }
}
