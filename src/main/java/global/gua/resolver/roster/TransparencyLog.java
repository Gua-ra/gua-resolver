package global.gua.resolver.roster;

/**
 * Append-only, Merkle-hash-chained log of every federation membership change (admit / update / suspend /
 * revoke / authority-set change). This is the "verifiability without PoW" core (CT / Sigstore Rekor /
 * Go checksum DB style): history cannot be retroactively altered, anyone can audit it, and resolvers
 * gossip checkpoints to detect split-views. See docs/FEDERATION_ROUTING_DESIGN.md §5.
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
     * one — the gossip check a mirror runs so the authority can't present a forked history.
     */
    boolean verifyConsistency(SignedRoster.LogCheckpoint older, SignedRoster.LogCheckpoint newer);
}
