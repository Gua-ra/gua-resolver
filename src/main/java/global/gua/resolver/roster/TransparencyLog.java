package global.gua.resolver.roster;

/**
 * Append-only, Merkle-hash-chained log of every federation membership change (admit / update / suspend /
 * revoke / authority-set change), plus POLICY_PUBLISH and DIRECTORY_CHECKPOINT leaves. This is the
 * "verifiability without PoW" core (CT / Sigstore Rekor / Go checksum DB style): appended history cannot be
 * rewritten without detection by a reader that compares against a checkpoint it saw earlier. Leaves carry
 * payload hashes, not payloads, and directory mutations are not logged, so an auditor can confirm that a
 * hash was appended, not replay the transition (ADM-001 L11). There is no checkpoint gossip between
 * resolvers; equivocation resistance needs witnesses and cross-channel comparison (ADM-001 L12).
 */
public interface TransparencyLog {

    /**
     * Leaf type for an accepted member self-signed entry (ADM-007). Its payload is the SHA-256 of the
     * {@code gua-member-entry.v1} canonical bytes, so the log commits to the exact entry that was accepted.
     * ADMIT and the status leaves are unchanged, so an admission carrying a member block appends two leaves.
     */
    String MEMBER_ATTEST = "MEMBER_ATTEST";

    /**
     * Leaf type for an accepted governance-signed registry epoch (ADM-001 L10). Its payload is the epoch
     * hash, the SHA-256 of the {@code gua-registry-epoch.v1} canonical bytes, so the log commits to the
     * exact epoch that changed membership and an auditor can tie every status change to a governance act.
     */
    String MEMBERSHIP_EPOCH = "MEMBERSHIP_EPOCH";

    /**
     * Leaf type for a status change requested while governance is required (ADM-001 L10). It records that
     * the operational key asked for a suspend or a revoke, not that one happened: nothing served changes
     * until a {@link #MEMBERSHIP_EPOCH} carries it. Without this leaf, a request governance never ratifies
     * would be auditable nowhere, which would leave the intent path the one part of the membership history
     * the log does not cover.
     */
    String STATUS_INTENT = "STATUS_INTENT";

    /**
     * Leaf type for a published account authority chain head (ADM-009 decision 12). Its payload is the
     * SHA-256 of the {@code gua-account-authority-head.v1} canonical bytes, so the log commits to the exact
     * head object a homeserver published, including the accountId and the head hash inside it.
     *
     * <p>This is the leaf ADM-009 decision 12 reserved and named as the thing whose absence leaves a class
     * {@code 0x00} account's chain an assertion by the homeserver that stores it. The leaf carries the hash
     * of the signed bytes and nothing else, so it commits to which head was published without putting an
     * accountId in the log's own columns, and the accountId is reachable only by someone who already holds
     * the published bytes.
     *
     * <p>The leaf is <b>not</b> evidence that the head is the account's latest: the log proves history, and
     * an authenticated state root that commits current state at one size is ADM-005's (requirement 3).
     */
    String ACCOUNT_AUTHORITY = "ACCOUNT_AUTHORITY";

    /** A single membership event (the leaf that gets hashed into the tree). */
    record Event(long index, String type, String homeserverId, String payloadHash, String recordedAt) {}

    /**
     * Append an event at a caller-supplied time; returns its checkpoint (root + size) after inclusion. The
     * caller passes the time when that same instant is the one it validated against, so the sequenced time
     * in the leaf is the acceptance time and not a second, slightly later reading of the clock (ADM-001 L11).
     */
    SignedRoster.LogCheckpoint append(String type, String homeserverId, String payloadHash,
                                      java.time.Instant recordedAt);

    /** Append an event now; returns its checkpoint (root + size) after inclusion. */
    default SignedRoster.LogCheckpoint append(String type, String homeserverId, String payloadHash) {
        return append(type, homeserverId, payloadHash, java.time.Instant.now());
    }

    /** Current checkpoint (Merkle root + tree size). */
    SignedRoster.LogCheckpoint head();

    /**
     * Verify that the given checkpoint is consistent with (an append-only extension of) a previously seen
     * one: the check a mirror runs against its own last checkpoint so a rewritten history is detected.
     */
    boolean verifyConsistency(SignedRoster.LogCheckpoint older, SignedRoster.LogCheckpoint newer);
}
