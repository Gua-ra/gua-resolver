/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.roster;

import java.nio.charset.StandardCharsets;

import global.gua.resolver.crypto.MerkleTree;

/**
 * The one definition of what a transparency-log leaf hashes over.
 *
 * <p>The preimage is {@code index|type|homeserverId|payloadHash|epochMillis}, and the leaf hash is the RFC
 * 6962 leaf hash of its UTF-8 bytes. The append path and every verifier that wants to recompute a leaf from
 * the fields the log serves call this, so the two can never drift: before this class the string was built
 * inline in {@code JdbcTransparencyLog.append} and a reader had to reproduce it from prose
 * ({@code PolicyLogController}).
 *
 * <p>Two things a reader has to get right, and both are why the function is here rather than in a comment.
 * The time in the preimage is epoch <b>milliseconds</b>, while the served event carries an ISO-8601 string, so
 * a verifier that formats rather than converts computes a different leaf. And a null homeserver id is the
 * empty string in the preimage, not the four characters {@code null}.
 */
public final class TransparencyLeaf {

    private TransparencyLeaf() {}

    /** The exact preimage string for a leaf. The delimiter cannot appear inside any field a leaf carries. */
    public static String data(long index, String type, String homeserverId, String payloadHash,
                              long recordedAtMillis) {
        return index + "|" + type + "|" + (homeserverId == null ? "" : homeserverId)
                + "|" + payloadHash + "|" + recordedAtMillis;
    }

    /** The RFC 6962 leaf hash (hex) of that preimage: what the Merkle tree is built over. */
    public static String hash(long index, String type, String homeserverId, String payloadHash,
                             long recordedAtMillis) {
        return MerkleTree.leafHash(
                data(index, type, homeserverId, payloadHash, recordedAtMillis)
                        .getBytes(StandardCharsets.UTF_8));
    }
}
