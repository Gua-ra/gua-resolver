package global.gua.resolver.roster;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import global.gua.resolver.crypto.MerkleTree;

/**
 * Leaves carry payload hashes only and directory mutations are not logged, so an auditor cannot replay
 * transitions. Without checkpoint gossip between resolvers the log alone does not detect a split view.
 */
public interface TransparencyLog {

    /**
     * Payload is the SHA-256 of the {@code gua-member-entry.v1} canonical bytes. A self-signed admission
     * appends ADMIT and then this leaf.
     */
    String MEMBER_ATTEST = "MEMBER_ATTEST";

    /** Payload is the epoch hash, the SHA-256 of the {@code gua-registry-epoch.v1} canonical bytes. */
    String MEMBERSHIP_EPOCH = "MEMBERSHIP_EPOCH";

    /**
     * A suspend or revoke requested under governance. It takes effect only when a {@link #MEMBERSHIP_EPOCH}
     * carries it.
     */
    String STATUS_INTENT = "STATUS_INTENT";

    record Event(long index, String type, String homeserverId, String payloadHash, String recordedAt) {

        public String leafHash() {
            String data = index + "|" + type + "|" + (homeserverId == null ? "" : homeserverId) + "|" + payloadHash
                    + "|" + Instant.parse(recordedAt).toEpochMilli();
            return MerkleTree.leafHash(data.getBytes(StandardCharsets.UTF_8));
        }
    }

    /** Pass the instant the caller validated against, so the leaf records the acceptance time. */
    SignedRoster.LogCheckpoint append(String type, String homeserverId, String payloadHash,
                                      java.time.Instant recordedAt);

    default SignedRoster.LogCheckpoint append(String type, String homeserverId, String payloadHash) {
        return append(type, homeserverId, payloadHash, java.time.Instant.now());
    }

    SignedRoster.LogCheckpoint head();

    boolean verifyConsistency(SignedRoster.LogCheckpoint older, SignedRoster.LogCheckpoint newer);
}
