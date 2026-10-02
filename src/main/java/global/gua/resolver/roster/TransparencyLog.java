package global.gua.resolver.roster;

/**
 * Append-only, Merkle-hash-chained log of every federation membership change (admit / update / suspend /
 * revoke / authority-set change), plus POLICY_PUBLISH and DIRECTORY_CHECKPOINT leaves. Appended history
 * cannot be rewritten without detection by a reader that compares against a checkpoint it saw earlier.
 * Leaves carry payload hashes, not payloads, and directory mutations are not logged, so an auditor can
 * confirm that a hash was appended, not replay the transition. There is no checkpoint gossip between
 * resolvers, so the log alone does not detect a split view.
 */
public interface TransparencyLog {

    /**
     * Leaf type for an accepted member self-signed entry. Its payload is the SHA-256 of the
     * {@code gua-member-entry.v1} canonical bytes, so the log commits to the exact entry that was accepted.
     * ADMIT and the status leaves are unchanged, so an admission carrying a member block appends two leaves.
     */
    String MEMBER_ATTEST = "MEMBER_ATTEST";

    /**
     * Leaf type for an accepted governance-signed registry epoch. Its payload is the epoch hash, the SHA-256
     * of the {@code gua-registry-epoch.v1} canonical bytes, so the log commits to the exact epoch that changed
     * membership and an auditor can tie every status change to a governance act.
     */
    String MEMBERSHIP_EPOCH = "MEMBERSHIP_EPOCH";

    /**
     * Leaf type for a status change requested while governance is required. It records that the operational
     * key asked for a suspend or a revoke, not that one happened: nothing served changes until a
     * {@link #MEMBERSHIP_EPOCH} carries it.
     */
    String STATUS_INTENT = "STATUS_INTENT";

    /** A single membership event (the leaf that gets hashed into the tree). */
    record Event(long index, String type, String homeserverId, String payloadHash, String recordedAt) {}

    /**
     * Append an event at a caller-supplied time; returns its checkpoint (root + size) after inclusion. The
     * caller passes the time when that same instant is the one it validated against, so the time in the leaf
     * is the acceptance time and not a second, slightly later reading of the clock.
     */
    SignedRoster.LogCheckpoint append(String type, String homeserverId, String payloadHash,
                                      java.time.Instant recordedAt);

    /** Append an event now; returns its checkpoint (root + size) after inclusion. */
    default SignedRoster.LogCheckpoint append(String type, String homeserverId, String payloadHash) {
        return append(type, homeserverId, payloadHash, java.time.Instant.now());
    }

    SignedRoster.LogCheckpoint head();

    /**
     * Verify that the given checkpoint is consistent with (an append-only extension of) a previously seen
     * one: the check a mirror runs against its own last checkpoint so a rewritten history is detected.
     */
    boolean verifyConsistency(SignedRoster.LogCheckpoint older, SignedRoster.LogCheckpoint newer);
}
