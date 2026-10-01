/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.placement.record.JdbcPlacementRecordStore;
import global.gua.resolver.placement.record.StoredPlacementRecord;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.MemberEntryJson;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Accepting and serving the published head of an account's authority chain (ADM-009 decision 12).
 *
 * <p>Entitlement, in full, because it is the part that decides what this endpoint is worth. A head is accepted
 * only from a homeserver that
 * <ul>
 *   <li>is an ACTIVE entry of this node's verified roster and signs with that entry's roster key
 *       ({@link AccountAuthorityHeadVerification}), which is the same bar a placement record clears;</li>
 *   <li>is the first homeserver to publish for that accountId, or the one that already holds it. A second
 *       homeserver's head is refused with {@link AccountAuthorityHeadRejection#AUTHORITY_CONFLICT}, never
 *       stored beside the first and never migrated: one account has one home (ADM-001 L9);</li>
 *   <li>does not contradict a placement record this node already holds for that accountId, when placement
 *       custody is on. That is the one piece of entitlement evidence the resolver has that does not come from
 *       the publisher itself, so it is used where it exists and its absence is not treated as agreement.</li>
 * </ul>
 *
 * <p>Movement is forward only, ordered on (headSeq, issuedAt): a greater sequence number is a new chain head,
 * and an equal sequence number with a newer issuedAt is the same head republished with a fresh validity
 * window, which is how a publisher keeps a head from going stale without the chain moving. Anything older is
 * refused and the stored head stands. The resolver cannot check chain continuity, because it holds no chain
 * records; it commits to what was published, and replaying the records up to that head hash is the reader's
 * half (ADM-009 decision 2 makes each record self-evidencing for exactly that purpose).
 *
 * <p>One {@code ACCOUNT_AUTHORITY} leaf is appended per accepted publication, with the SHA-256 of the received
 * canonical bytes as its payload. That is the leaf decision 12 reserves and nothing more: the log commits which
 * head bytes a homeserver published, not the chain records behind them and not anything about whether the
 * transition was legitimate. The cost is stated in {@code application.yml}: the log size is the roster version
 * and the weighted fallback seeds on it, so every leaf moves new-account placement (ADM-001 L6). The
 * publication is idempotent on the payload hash, so a retry appends nothing.
 *
 * <p>Deliberately not transactional, for the same reason the placement store is not: every write is a single
 * statement whose WHERE clause carries the condition it depends on. The row is written before its leaf is
 * appended, so a crash in between leaves a head that is stored and not yet anchored, which the proof read
 * reports as such and re-presenting the head repairs. The other order would append a leaf for a head this node
 * does not serve, into a log that cannot retract one.
 */
@Service
@ConditionalOnExpression(AccountAuthorityFeature.ENABLED)
public class AccountAuthorityHeadService {

    private static final Logger log = LoggerFactory.getLogger(AccountAuthorityHeadService.class);

    /** What an accepted publication did. */
    public enum Outcome { STORED, REPLACED, UNCHANGED }

    private final AccountAuthorityHeadVerifier verifier;
    private final JdbcAccountAuthorityHeadStore store;
    private final JdbcTransparencyLog transparencyLog;
    private final RosterStore rosterStore;
    private final ObjectProvider<JdbcPlacementRecordStore> placementRecords;
    private final ObjectMapper json;
    private final MeterRegistry metrics;
    private final Counter conflicts;

    public AccountAuthorityHeadService(AccountAuthorityHeadVerifier verifier,
                                       JdbcAccountAuthorityHeadStore store,
                                       JdbcTransparencyLog transparencyLog,
                                       RosterStore rosterStore,
                                       ObjectProvider<JdbcPlacementRecordStore> placementRecords,
                                       ObjectMapper json, MeterRegistry metrics) {
        this.verifier = verifier;
        this.store = store;
        this.transparencyLog = transparencyLog;
        this.rosterStore = rosterStore;
        this.placementRecords = placementRecords;
        this.json = json;
        this.metrics = metrics;
        this.conflicts = Counter.builder("gua.resolver.account.authority.head.conflicts").register(metrics);
    }

    /**
     * Parse, authenticate and store one presented envelope, and anchor it in the log. The body is read through
     * the strict reader, so an unknown field, a duplicate key or trailing content is refused rather than
     * silently dropped: a signature must never cover fewer fields than the resolver goes on to store.
     */
    public Outcome publish(byte[] body, Instant now) {
        try {
            AccountAuthorityHeadEnvelope envelope;
            try {
                envelope = MemberEntryJson.read(json, body, AccountAuthorityHeadEnvelope.class);
            } catch (MemberEntryJson.MalformedMemberEntryException e) {
                throw new AccountAuthorityHeadException(
                        AccountAuthorityHeadRejection.MALFORMED_ENVELOPE);
            }
            AccountAuthorityHeadVerification.Verified verified = verifier.verify(envelope, now);
            String payloadHash = MerkleTree.sha256Hex(verified.canonical());
            Outcome outcome = store(verified, payloadHash, now);
            metrics.counter("gua.resolver.account.authority.heads.accepted",
                    "result", outcome.name().toLowerCase(Locale.ROOT)).increment();
            return outcome;
        } catch (AccountAuthorityHeadException e) {
            metrics.counter("gua.resolver.account.authority.head.rejections",
                    "reason", e.reason()).increment();
            throw e;
        }
    }

    /** Refuse a publication before anything is parsed, when the flag is off. Reads are unaffected. */
    public void requireIngestEnabled(boolean enabled) {
        if (!enabled) {
            AccountAuthorityHeadException e = new AccountAuthorityHeadException(
                    AccountAuthorityHeadRejection.INGEST_DISABLED);
            metrics.counter("gua.resolver.account.authority.head.rejections", "reason", e.reason())
                    .increment();
            throw e;
        }
    }

    public Optional<StoredAccountAuthorityHead> find(String accountId) {
        return store.find(accountId);
    }

    /**
     * The proof for a stored head: the envelope verbatim, its leaf, the audit path, and the checkpoint the path
     * was computed against.
     *
     * <p>The checkpoint is the one the currently served roster commits to, not the current log head, because
     * the root a reader can authenticate is the one inside the roster's signed canonical bytes. A proof against
     * a newer, unsigned head would verify against nothing.
     */
    public AccountAuthorityHeadProof proof(StoredAccountAuthorityHead head) {
        Long leafIndex = head.logLeafIndex();
        if (leafIndex == null) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.HEAD_NOT_ANCHORED);
        }
        SignedRoster roster = rosterStore.current();
        SignedRoster.LogCheckpoint checkpoint = roster.logCheckpoint();
        if (checkpoint == null || leafIndex >= checkpoint.size()) {
            // The signed roster has not caught up with the leaf yet. Rebuilding is what the roster store does
            // when the log grows, so ask for it rather than serving a proof against a root nobody signed.
            roster = rosterStore.refresh();
            checkpoint = roster.logCheckpoint();
        }
        if (checkpoint == null || leafIndex >= checkpoint.size()) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.HEAD_NOT_ANCHORED);
        }
        JdbcTransparencyLog.Leaf leaf = transparencyLog.leaf(leafIndex)
                .orElseThrow(() -> new AccountAuthorityHeadException(
                        AccountAuthorityHeadRejection.HEAD_NOT_ANCHORED));
        if (!TransparencyLog.ACCOUNT_AUTHORITY.equals(leaf.type())
                || !head.payloadHashHex().equals(leaf.payloadHash())) {
            // The row points at a leaf that does not commit these bytes. Serve nothing rather than a proof a
            // reader would (correctly) read as a forgery.
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.HEAD_NOT_ANCHORED);
        }
        List<String> auditPath = transparencyLog.inclusionProof(leafIndex, (int) checkpoint.size());
        return new AccountAuthorityHeadProof(
                head.envelope(),
                new AccountAuthorityHeadProof.Leaf(leaf.index(), leaf.type(), leaf.homeserverId(),
                        leaf.payloadHash(), leaf.recordedAtMillis(), leaf.leafHash()),
                auditPath, checkpoint, roster.version());
    }

    private Outcome store(AccountAuthorityHeadVerification.Verified verified, String payloadHash,
                          Instant now) {
        StoredAccountAuthorityHead incoming =
                StoredAccountAuthorityHead.of(verified, payloadHash, now);
        requirePlacementAgrees(incoming);
        Optional<StoredAccountAuthorityHead> existing = store.find(incoming.accountId());
        if (existing.isEmpty()) {
            try {
                store.insert(incoming);
            } catch (DuplicateKeyException e) {
                // Another publication won the race for this accountId; decide against what it wrote.
                StoredAccountAuthorityHead raced = store.find(incoming.accountId())
                        .orElseThrow(() -> new AccountAuthorityHeadException(
                                AccountAuthorityHeadRejection.AUTHORITY_CONFLICT));
                return reconcile(raced, incoming);
            }
            anchor(incoming);
            return Outcome.STORED;
        }
        return reconcile(existing.get(), incoming);
    }

    private Outcome reconcile(StoredAccountAuthorityHead held, StoredAccountAuthorityHead incoming) {
        if (!held.homeserverId().equals(incoming.homeserverId())) {
            // accountIds are not identifiers, so the pair is safe to log and is what an operator needs to tell
            // a duplicated account from a member publishing for accounts it does not hold.
            log.error("Authority head conflict for accountId={}: published by homeserverId={}, claimed by "
                            + "homeserverId={}; keeping the published head",
                    held.accountId(), held.homeserverId(), incoming.homeserverId());
            conflicts.increment();
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.AUTHORITY_CONFLICT);
        }
        if (held.sameSignedBytesAs(incoming)) {
            // The same bytes again: a retry, not a new publication. It is also the repair path for a head that
            // was stored before its leaf was appended, so presenting it again anchors it.
            anchor(held);
            return Outcome.UNCHANGED;
        }
        boolean newer = incoming.headSeq() > held.headSeq()
                || (incoming.headSeq() == held.headSeq()
                        && incoming.issuedAt().isAfter(held.issuedAt()));
        if (!newer) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.STALE_HEAD);
        }
        if (store.replaceIfNewer(incoming) == 0) {
            // A concurrent publication already stored something at least as new; the newer head stands.
            return Outcome.UNCHANGED;
        }
        anchor(incoming);
        return Outcome.REPLACED;
    }

    /**
     * A published head must not contradict a placement record this node holds. Placement custody is a separate
     * flag, so the store may not exist; when it does not, there is nothing to compare and this is silent
     * rather than permissive by assertion.
     */
    private void requirePlacementAgrees(StoredAccountAuthorityHead incoming) {
        JdbcPlacementRecordStore records = placementRecords.getIfAvailable();
        if (records == null) {
            return;
        }
        Optional<StoredPlacementRecord> placed = records.find(incoming.accountId());
        if (placed.isPresent() && !placed.get().homeserverId().equals(incoming.homeserverId())) {
            log.error("Authority head for accountId={} published by homeserverId={} while placement holds "
                            + "homeserverId={}; refusing",
                    incoming.accountId(), incoming.homeserverId(), placed.get().homeserverId());
            throw new AccountAuthorityHeadException(
                    AccountAuthorityHeadRejection.PLACEMENT_DISAGREES);
        }
    }

    /**
     * Append the leaf for this head, or reuse the one that already commits these exact bytes, and record its
     * index on the row. Idempotent on the payload hash, so a retry costs no leaf: every appended leaf moves the
     * roster version and with it every new-account fallback decision (ADM-001 L6).
     */
    private void anchor(StoredAccountAuthorityHead head) {
        if (head.logLeafIndex() != null) {
            return;
        }
        long leafIndex = transparencyLog
                .findLeafIndex(TransparencyLog.ACCOUNT_AUTHORITY, head.payloadHashHex())
                .orElseGet(() -> transparencyLog.append(TransparencyLog.ACCOUNT_AUTHORITY,
                        head.homeserverId(), head.payloadHashHex(), head.receivedAt()).size() - 1);
        store.anchor(head.accountId(), head.payloadHashHex(), leafIndex);
    }
}
