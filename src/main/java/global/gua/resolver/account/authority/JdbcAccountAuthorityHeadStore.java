/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

/**
 * Custody of {@code account_authority_head}: the published head of one account's authority chain, held on the
 * authority node only in this phase (mirror replication is ADM-001 O12).
 *
 * <p>The accountId is the primary key, so one account has one published head by construction rather than by
 * convention: a second homeserver's claim collides on insert instead of overwriting. The received bytes and
 * signature are stored as text and never rewritten.
 *
 * <p>Movement is forward only, ordered on (headSeq, issuedAt), and the guard is in the WHERE clause rather than
 * only in the service: the publishing homeserver id and that order are conditions of the update, so a
 * concurrent write can never move a head to another homeserver or backwards. What it cannot check is chain
 * continuity: the
 * resolver holds no chain records, so it cannot tell that a head at seq n+1 actually follows the one at seq n.
 * That is the reader's job, by replaying the self-evidencing records from the homeserver up to the head hash
 * the log committed (ADM-009 decision 2).
 *
 * <p>Timestamps are stored as UTC {@link LocalDateTime} rather than through the JVM's default zone, the same
 * rule the placement records follow, because these are signed values: a zone change or a daylight-saving fold
 * must not be able to move a stored window away from the one the signature covers.
 */
@Component
@ConditionalOnExpression(AccountAuthorityFeature.ENABLED)
public class JdbcAccountAuthorityHeadStore {

    private static final String COLUMNS = "account_id, homeserver_id, head_hash, head_seq, issued_at, "
            + "not_before, not_after, record_b64, signature_b64, payload_hash, log_leaf_index, received_at";

    private final JdbcTemplate jdbc;

    public JdbcAccountAuthorityHeadStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    private final RowMapper<StoredAccountAuthorityHead> mapper = (rs, n) -> new StoredAccountAuthorityHead(
            rs.getString("account_id"),
            rs.getString("homeserver_id"),
            rs.getString("head_hash"),
            rs.getLong("head_seq"),
            instant(rs, "issued_at"),
            instant(rs, "not_before"),
            instant(rs, "not_after"),
            rs.getString("record_b64"),
            rs.getString("signature_b64"),
            rs.getString("payload_hash"),
            leafIndex(rs),
            instant(rs, "received_at"));

    /** The published head for one accountId. */
    public Optional<StoredAccountAuthorityHead> find(String accountId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM account_authority_head WHERE account_id = ?",
                mapper, accountId).stream().findFirst();
    }

    /** Insert a head for an accountId that has none yet; collides rather than overwrites. */
    public void insert(StoredAccountAuthorityHead head) {
        jdbc.update("INSERT INTO account_authority_head (" + COLUMNS
                        + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                head.accountId(), head.homeserverId(), head.headHashHex(), head.headSeq(),
                utc(head.issuedAt()), utc(head.notBefore()), utc(head.notAfter()),
                head.recordB64(), head.signatureB64(), head.payloadHashHex(), head.logLeafIndex(),
                utc(head.receivedAt()));
    }

    /**
     * Replace a head the same homeserver re-published, and only when it is strictly newer in the order the
     * service defines: a greater head sequence number, or the same sequence number with a newer issuedAt,
     * which is the same head republished with a fresh validity window. Zero rows updated means someone else
     * already wrote a head at least as new, and the newer one stands.
     *
     * <p>Both conditions are in the WHERE clause rather than only in the service, so a concurrent write can
     * never move a head to another homeserver, backwards in the chain, or backwards in time within one
     * sequence number.
     *
     * <p>The new row's leaf index starts null: the leaf for it is appended after the row is written, so a
     * crash in between leaves a head that is stored and not yet anchored rather than a row pointing at a leaf
     * that commits the previous head.
     */
    public int replaceIfNewer(StoredAccountAuthorityHead head) {
        return jdbc.update("""
                UPDATE account_authority_head
                   SET head_hash = ?, head_seq = ?, issued_at = ?, not_before = ?, not_after = ?,
                       record_b64 = ?, signature_b64 = ?, payload_hash = ?, log_leaf_index = NULL,
                       received_at = ?
                 WHERE account_id = ? AND homeserver_id = ?
                   AND (head_seq < ? OR (head_seq = ? AND issued_at < ?))
                """,
                head.headHashHex(), head.headSeq(), utc(head.issuedAt()), utc(head.notBefore()),
                utc(head.notAfter()), head.recordB64(), head.signatureB64(), head.payloadHashHex(),
                utc(head.receivedAt()),
                head.accountId(), head.homeserverId(),
                head.headSeq(), head.headSeq(), utc(head.issuedAt()));
    }

    /**
     * Record which leaf committed the head this row currently holds. The payload hash is in the WHERE clause,
     * so a leaf index can only ever be attached to the exact bytes it was computed over: if a newer head has
     * replaced this row in the meantime, this update matches nothing instead of labelling the new bytes with
     * the old leaf.
     */
    public int anchor(String accountId, String payloadHashHex, long leafIndex) {
        return jdbc.update("""
                UPDATE account_authority_head
                   SET log_leaf_index = ?
                 WHERE account_id = ? AND payload_hash = ? AND log_leaf_index IS NULL
                """, leafIndex, accountId, payloadHashHex);
    }

    public long count() {
        Long n = jdbc.queryForObject("SELECT COUNT(*) FROM account_authority_head", Long.class);
        return n == null ? 0L : n;
    }

    private static Long leafIndex(ResultSet rs) throws SQLException {
        long value = rs.getLong("log_leaf_index");
        return rs.wasNull() ? null : value;
    }

    private static LocalDateTime utc(Instant instant) {
        return instant == null ? null : LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        LocalDateTime value = rs.getObject(column, LocalDateTime.class);
        return value == null ? null : value.toInstant(ZoneOffset.UTC);
    }
}
