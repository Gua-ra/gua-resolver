/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.verify;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import global.gua.resolver.account.authority.AccountAuthorityHead;
import global.gua.resolver.account.authority.AccountAuthorityHeadException;
import global.gua.resolver.account.authority.AccountAuthorityHeadProof;
import global.gua.resolver.account.authority.AccountAuthorityHeadRejection;
import global.gua.resolver.account.authority.AccountAuthorityHeadVerification;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLeaf;
import global.gua.resolver.roster.TransparencyLog;

/**
 * The reader's half of ADM-009 decision 12: check that the authority chain head a homeserver just served is the
 * head that homeserver published, signed and got anchored in the transparency log.
 *
 * <p>This is a library function with no Spring, no database and no clock of its own, so a client port (iOS,
 * Android, web) is a translation of this file rather than a reinterpretation of prose. {@link ResolverVerifier}
 * exposes it with the roster trust root already applied, which is how a caller should normally reach it.
 *
 * <p>What a caller brings:
 * <ol>
 *   <li>the head its own homeserver served over an authenticated channel: accountId, headHash, headSeq. On
 *       Gua clients that is {@code GET /account/authority}, which is bearer-authenticated and own-account
 *       only, so today the account holder's own devices are the verifiers this reaches;</li>
 *   <li>the proof from the resolver: the signed head bytes, the leaf, the audit path and the checkpoint the
 *       path was computed against;</li>
 *   <li>a roster it has verified k-of-n against its pinned authority keys, whose {@code logCheckpoint} is the
 *       only log root that carries a signature;</li>
 *   <li>optionally, consistency proofs, when its roster is newer than the checkpoint the audit path was built
 *       at, or newer than the last checkpoint this reader verified.</li>
 * </ol>
 *
 * <p>The order of the checks is the order they are written in, and it is the same shape as the placement
 * ingest: the bytes, then the roster and the signature, then the log, then the claim. That ordering is what
 * makes the failure reasons meaningful, because nothing later is reached with unauthenticated bytes.
 *
 * <p>What passing this check does and does not establish.
 * <ul>
 *   <li><b>Does:</b> the head was published by the homeserver named in the signed bytes, under the roster key
 *       admission proved that member holds; those exact bytes are committed by leaf {@code index} of the log;
 *       and that leaf is in the tree whose root the authority signed inside the roster. A homeserver that shows
 *       two devices two different heads for one account now has to produce two published, logged heads, which
 *       is a contradiction anyone holding both can show a third party.</li>
 *   <li><b>Does not:</b> prove that this head is the account's <b>latest</b>. The log commits history, not
 *       current state; there is no authenticated state root in the resolver (ADM-005 requirement 3), and no
 *       non-membership proof, so a withheld transition is indistinguishable from one that never happened
 *       (ADM-005 requirement 9). Remembering the highest headSeq it has ever verified narrows a caller's
 *       exposure to "a head it has never seen can be hidden from it", and closing that is ADM-005's.</li>
 *   <li><b>Does not:</b> rule out equivocation by the resolver. Nothing witnesses or co-signs the checkpoint,
 *       so two readers can be served two consistent-looking views (ADM-001 L12). The consistency step below
 *       only proves the log was not rewritten relative to a checkpoint this same reader held before.</li>
 * </ul>
 */
public final class AccountAuthorityHeadCheck {

    /** The default clock skew a reader allows on a head's window, matching the resolver's claims skew. */
    public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofMinutes(2);

    /** The default longest window a reader accepts on a head object, matching the resolver's own cap. */
    public static final Duration DEFAULT_MAX_VALIDITY = Duration.ofDays(400);

    private AccountAuthorityHeadCheck() {}

    /** What the caller's own homeserver told it the head is, and what the published head must therefore say. */
    public record Expected(String accountId, String headHashHex, long headSeq) {}

    /**
     * The checkpoint steps a reader may have to bridge, each with its own proof, because the log moves between
     * requests and a reader keeps its own history.
     *
     * @param toSignedFromProof  consistency proof from the checkpoint the audit path was computed against to
     *                           the one inside the signed roster, or null when they are the same checkpoint
     * @param lastSeen           the newest checkpoint this reader verified before, or null on a first run
     * @param toSignedFromLastSeen consistency proof from {@code lastSeen} to the signed checkpoint, or null
     *                           when they are the same checkpoint
     */
    public record Consistency(List<String> toSignedFromProof, SignedRoster.LogCheckpoint lastSeen,
                              List<String> toSignedFromLastSeen) {

        /** A reader with no history, verifying against the same checkpoint the proof was built at. */
        public static Consistency none() {
            return new Consistency(null, null, null);
        }
    }

    /**
     * The verified outcome: the decoded head, the leaf index that commits it, and the checkpoint the inclusion
     * was proved against. A caller stores {@code checkpoint} as the checkpoint to demand consistency with next
     * time, and {@code head.headSeq()} as the highest sequence number it has seen.
     */
    public record Result(AccountAuthorityHead head, long leafIndex,
                         SignedRoster.LogCheckpoint checkpoint) {}

    /**
     * Run the check with the default skew and validity cap.
     *
     * @param verifiedRoster a roster the caller has already verified k-of-n; this function does not verify it
     */
    public static Result check(Expected expected, AccountAuthorityHeadProof proof,
                               Consistency consistency, SignedRoster verifiedRoster, Instant now) {
        return check(expected, proof, consistency, verifiedRoster, now,
                DEFAULT_CLOCK_SKEW, DEFAULT_MAX_VALIDITY);
    }

    /**
     * Check a published head against what the account's own homeserver served, or refuse with one reason.
     *
     * @param expected       accountId, head hash and head sequence number as the homeserver served them
     * @param proof          the resolver's proof: envelope, leaf, audit path, checkpoint
     * @param consistency    the checkpoint steps to bridge and their proofs; {@link Consistency#none()} when
     *                       the reader has no history and the proof was built at the signed checkpoint
     * @param verifiedRoster a roster the caller verified k-of-n against its pinned authority keys
     * @param now            the reader's clock
     * @param clockSkew      how far the reader lets the clocks disagree
     * @param maxValidity    the longest window the reader accepts on a head object
     */
    public static Result check(Expected expected, AccountAuthorityHeadProof proof,
                               Consistency consistency, SignedRoster verifiedRoster, Instant now,
                               Duration clockSkew, Duration maxValidity) {
        Consistency steps = consistency == null ? Consistency.none() : consistency;
        if (expected == null || proof == null || proof.leaf() == null || proof.auditPath() == null
                || proof.checkpoint() == null) {
            throw new AccountAuthorityHeadException(
                    AccountAuthorityHeadRejection.MALFORMED_ENVELOPE);
        }
        if (verifiedRoster == null || verifiedRoster.logCheckpoint() == null) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.ROSTER_UNVERIFIED);
        }

        // 1. The bytes, the publisher's roster key and the window. Shared with the resolver's own ingest, so
        // the reader and the node that accepted the head apply one definition of a valid head.
        AccountAuthorityHeadVerification.Verified verified = AccountAuthorityHeadVerification.verify(
                proof.envelope(), verifiedRoster, now, clockSkew, maxValidity);
        AccountAuthorityHead head = verified.head();

        // 2. The leaf has to describe these bytes, published by this signer, as an authority-head leaf. A leaf
        // for some other object, or for another account's head, cannot stand in for this one.
        AccountAuthorityHeadProof.Leaf leaf = proof.leaf();
        if (!TransparencyLog.ACCOUNT_AUTHORITY.equals(leaf.type())) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.LEAF_TYPE_MISMATCH);
        }
        if (!head.homeserverId().equals(leaf.publisherId())) {
            throw new AccountAuthorityHeadException(
                    AccountAuthorityHeadRejection.LEAF_PUBLISHER_MISMATCH);
        }
        if (!MerkleTree.sha256Hex(verified.canonical()).equals(leaf.payloadHash())) {
            throw new AccountAuthorityHeadException(
                    AccountAuthorityHeadRejection.PAYLOAD_HASH_MISMATCH);
        }

        // 3. The leaf hash is recomputed from the leaf's own fields, never taken from the server. Without this
        // step a server could serve a genuine leaf hash from elsewhere in the tree beside made-up fields.
        String leafHash = TransparencyLeaf.hash(leaf.index(), leaf.type(), leaf.publisherId(),
                leaf.payloadHash(), leaf.recordedAtMillis());
        if (!leafHash.equals(leaf.leafHash())) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.LEAF_HASH_MISMATCH);
        }

        // 4. The leaf is in the tree the proof's checkpoint names.
        SignedRoster.LogCheckpoint checkpoint = proof.checkpoint();
        if (!MerkleTree.verifyInclusion((int) leaf.index(), (int) checkpoint.size(), leafHash,
                checkpoint.merkleRoot(), proof.auditPath())) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.LEAF_NOT_INCLUDED);
        }

        // 5. That checkpoint has to be one the authority signed. The only signed log root is the one inside the
        // roster's canonical bytes, so either it is that root, or the signed root provably extends it: the log
        // grows between two requests, and a reader must not have to fetch both in one instant.
        SignedRoster.LogCheckpoint signed = verifiedRoster.logCheckpoint();
        requireExtends(checkpoint, signed, steps.toSignedFromProof());

        // 6. The signed checkpoint must extend the newest one this reader already verified, which is what makes
        // a rewritten history visible to it (and only to it: see the class note on equivocation).
        if (steps.lastSeen() != null) {
            requireExtends(steps.lastSeen(), signed, steps.toSignedFromLastSeen());
        }

        // 7. Finally, the claim: the logged head is this account's, and it is the head the homeserver served.
        // These three comparisons are the whole point of the exercise, and they come last because until now
        // nothing had been authenticated enough for a mismatch to mean anything.
        if (!head.accountId().equals(expected.accountId())) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.ACCOUNT_MISMATCH);
        }
        if (!head.headHashHex().equalsIgnoreCase(expected.headHashHex())) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.HEAD_HASH_MISMATCH);
        }
        if (head.headSeq() != expected.headSeq()) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.HEAD_SEQ_MISMATCH);
        }

        return new Result(head, leaf.index(), signed);
    }

    /**
     * Require that {@code newer} is {@code older} itself or a proven append-only extension of it. A missing
     * proof is a refusal, never an assumption: the two checkpoints being different is exactly the case a proof
     * exists for.
     */
    private static void requireExtends(SignedRoster.LogCheckpoint older, SignedRoster.LogCheckpoint newer,
                                       List<String> proof) {
        if (sameCheckpoint(older, newer)) {
            return;
        }
        if (older.size() > newer.size()
                || proof == null
                || !MerkleTree.verifyConsistency((int) older.size(), (int) newer.size(),
                        older.merkleRoot(), newer.merkleRoot(), proof)) {
            throw new AccountAuthorityHeadException(
                    AccountAuthorityHeadRejection.CHECKPOINT_NOT_EXTENDED);
        }
    }

    private static boolean sameCheckpoint(SignedRoster.LogCheckpoint a, SignedRoster.LogCheckpoint b) {
        return a.size() == b.size() && a.merkleRoot().equals(b.merkleRoot());
    }
}
