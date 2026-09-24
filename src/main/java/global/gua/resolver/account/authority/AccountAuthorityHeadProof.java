/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.util.List;

import global.gua.resolver.roster.SignedRoster;

/**
 * Everything a reader needs to check one published head, and nothing it has to take on trust from the server:
 * the signed head bytes, the log leaf that committed them, the audit path, and the checkpoint the path was
 * computed against (ADM-009 decision 12).
 *
 * <p>The three parts answer three different questions. The envelope answers "who published this head, and is
 * it the head my own homeserver just told me about" and is verified under a roster key. The leaf answers
 * "which log entry commits these exact bytes" and is verified by recomputing the leaf hash from its own
 * fields. The audit path and checkpoint answer "is that entry in the log the authority signed" and are
 * verified against the root inside the signed roster's canonical bytes.
 *
 * <p>The checkpoint here is the one the audit path was computed against, which is the checkpoint the currently
 * served roster commits to. A reader whose roster is newer verifies the step between them with a consistency
 * proof from {@code GET /roster/log/consistency}; that is the one case where a served proof and a served
 * roster legitimately disagree, because the log moves between two requests.
 *
 * <p>The leaf's time is epoch milliseconds, not an ISO-8601 string, because milliseconds are what the leaf
 * preimage hashes over. Serving the formatted form here would leave every reader to convert it back, and a
 * reader that converted it differently would compute a different leaf hash and read a valid proof as a forged
 * one.
 */
public record AccountAuthorityHeadProof(
        AccountAuthorityHeadEnvelope envelope,
        Leaf leaf,
        List<String> auditPath,
        SignedRoster.LogCheckpoint checkpoint,
        long rosterVersion) {

    /**
     * The log leaf, field for field as its preimage carries them.
     *
     * @param index            the leaf's position in the tree
     * @param type             always {@code ACCOUNT_AUTHORITY} for a head leaf
     * @param publisherId      the publishing homeserver's roster id, the leaf's {@code homeserverId} field
     * @param payloadHash      SHA-256 of the canonical head bytes, hex
     * @param recordedAtMillis the sequenced time, epoch milliseconds
     * @param leafHash         the RFC 6962 leaf hash the tree was built with, hex
     */
    public record Leaf(long index, String type, String publisherId, String payloadHash,
                       long recordedAtMillis, String leafHash) {}
}
