package global.gua.resolver.roster;

/** Leaves carry payload hashes, not payloads. */
public interface TransparencyLog {

    /** Payload: SHA-256 of the gua-member-entry.v1 canonical bytes. */
    String MEMBER_ATTEST = "MEMBER_ATTEST";

    /** Payload: the epoch hash. */
    String MEMBERSHIP_EPOCH = "MEMBERSHIP_EPOCH";

    /** A status change requested under governance; nothing served changes until a MEMBERSHIP_EPOCH. */
    String STATUS_INTENT = "STATUS_INTENT";

    record Event(long index, String type, String homeserverId, String payloadHash, String recordedAt) {}

    /** The caller passes the instant it validated against, so the leaf time is the acceptance time. */
    SignedRoster.LogCheckpoint append(String type, String homeserverId, String payloadHash,
                                      java.time.Instant recordedAt);

    default SignedRoster.LogCheckpoint append(String type, String homeserverId, String payloadHash) {
        return append(type, homeserverId, payloadHash, java.time.Instant.now());
    }

    SignedRoster.LogCheckpoint head();

    boolean verifyConsistency(SignedRoster.LogCheckpoint older, SignedRoster.LogCheckpoint newer);
}
