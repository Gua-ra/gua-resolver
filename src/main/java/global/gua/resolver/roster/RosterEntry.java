package global.gua.resolver.roster;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.ClaimPredicate;

/** member is null for an unattested entry and omitted from the JSON, keeping the earlier wire format. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RosterEntry(
        Homeserver homeserver,
        List<ClaimPredicate> claims,
        Instant admittedAt,
        Status status,
        @JsonInclude(JsonInclude.Include.NON_NULL) MemberAttestation member) {

    /** PENDING is an admission awaiting a governance epoch. */
    public enum Status { ACTIVE, SUSPENDED, REVOKED, PENDING }

    public RosterEntry(Homeserver homeserver, List<ClaimPredicate> claims, Instant admittedAt, Status status) {
        this(homeserver, claims, admittedAt, status, null);
    }

    public RosterEntry withMember(MemberAttestation attestation) {
        return new RosterEntry(homeserver, claims, admittedAt, status, attestation);
    }

    @JsonIgnore
    public boolean isActive() {
        return status == Status.ACTIVE;
    }

    @JsonIgnore
    public boolean isPending() {
        return status == Status.PENDING;
    }
}
