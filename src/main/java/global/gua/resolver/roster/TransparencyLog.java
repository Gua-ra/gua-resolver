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

    /** A single membership event (the leaf that gets hashed into the tree). */
    record Event(long index, String type, String homeserverId, String payloadHash, String recordedAt) {}

    /** Append an event; returns its checkpoint (root + size) after inclusion. */
    SignedRoster.LogCheckpoint append(String type, String homeserverId, String payloadHash);

    /** Current checkpoint (Merkle root + tree size). */
    SignedRoster.LogCheckpoint head();

    /**
     * Verify that the given checkpoint is consistent with (an append-only extension of) a previously seen
     * one: the check a mirror runs against its own last checkpoint so a rewritten history is detected.
     */
    boolean verifyConsistency(SignedRoster.LogCheckpoint older, SignedRoster.LogCheckpoint newer);
}
