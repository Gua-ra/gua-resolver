package global.gua.resolver.placement.record;

import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

import global.gua.resolver.crypto.MerkleTree;

/**
 * Custody of {@code placement_record}: the first per-account replicated federation state, held on the
 * authority node only in this phase (mirror replication is ADM-001 O12).
 *
 * <p>The accountId is the primary key, so one accountId has one home by construction rather than by
 * convention: a second homeserver's claim collides on insert instead of overwriting. The received bytes and
 * signature are stored as text and never rewritten.
 *
 * <p>Timestamps are stored as UTC {@link LocalDateTime} rather than through the JVM's default zone, the same
 * rule the roster attestations follow, because these are signed values: a zone change or a daylight-saving
 * fold must not be able to move a stored window away from the one the signature covers.
 */
@Component
@ConditionalOnExpression(PlacementFeature.ENABLED)
public class JdbcPlacementRecordStore {

    private static final String COLUMNS = "account_id, homeserver_id, generation, origin, issued_at, "
            + "not_before, not_after, record_b64, signature_b64, received_at";

    private final JdbcTemplate jdbc;

    public JdbcPlacementRecordStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    private final RowMapper<StoredPlacementRecord> mapper = (rs, n) -> new StoredPlacementRecord(
            rs.getString("account_id"),
            rs.getString("homeserver_id"),
            rs.getInt("generation"),
            PlacementRecord.Origin.valueOf(rs.getString("origin")),
            instant(rs, "issued_at"),
            instant(rs, "not_before"),
            instant(rs, "not_after"),
            rs.getString("record_b64"),
            rs.getString("signature_b64"),
            instant(rs, "received_at"));

    /** One record by its accountId. */
    public Optional<StoredPlacementRecord> find(String accountId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM placement_record WHERE account_id = ?",
                mapper, accountId).stream().findFirst();
    }

    /** Insert a record for an accountId that has no home yet; collides rather than overwrites. */
    public void insert(StoredPlacementRecord record) {
        jdbc.update("INSERT INTO placement_record (" + COLUMNS + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                record.accountId(), record.homeserverId(), record.generation(), record.origin().name(),
                utc(record.issuedAt()), utc(record.notBefore()), utc(record.notAfter()),
                record.recordB64(), record.signatureB64(), utc(record.receivedAt()));
    }

    /**
     * Replace a record the same homeserver re-issued, and only when the new one is strictly newer. The
     * homeserver id and the issuedAt floor are in the WHERE clause, so a concurrent write can never move a
     * record to another homeserver or backwards in time; zero rows updated means someone else already wrote
     * a newer one.
     */
    public int replaceIfNewer(StoredPlacementRecord record) {
        return jdbc.update("""
                UPDATE placement_record
                   SET generation = ?, origin = ?, issued_at = ?, not_before = ?, not_after = ?,
                       record_b64 = ?, signature_b64 = ?, received_at = ?
                 WHERE account_id = ? AND homeserver_id = ? AND issued_at < ?
                """,
                record.generation(), record.origin().name(), utc(record.issuedAt()),
                utc(record.notBefore()), utc(record.notAfter()), record.recordB64(),
                record.signatureB64(), utc(record.receivedAt()),
                record.accountId(), record.homeserverId(), utc(record.issuedAt()));
    }

    /** One page of a homeserver's records, ordered by accountId, for reconciliation. */
    public List<StoredPlacementRecord> listByHomeserver(String homeserverId, String afterAccountId,
                                                        int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM placement_record "
                        + "WHERE homeserver_id = ? AND account_id > ? ORDER BY account_id LIMIT ?",
                mapper, homeserverId, afterAccountId == null ? "" : afterAccountId, limit);
    }

    /** One page of every record, ordered by accountId, for the auditor's sweep. */
    public List<StoredPlacementRecord> page(String afterAccountId, int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM placement_record "
                        + "WHERE account_id > ? ORDER BY account_id LIMIT ?",
                mapper, afterAccountId == null ? "" : afterAccountId, limit);
    }

    public long count() {
        Long n = jdbc.queryForObject("SELECT COUNT(*) FROM placement_record", Long.class);
        return n == null ? 0L : n;
    }

    /** How many records each homeserver holds, split by origin, for the gauge. */
    public List<OriginCount> counts() {
        return jdbc.query("SELECT homeserver_id, origin, COUNT(*) AS n FROM placement_record "
                        + "GROUP BY homeserver_id, origin",
                (rs, n) -> new OriginCount(rs.getString("homeserver_id"), rs.getString("origin"),
                        rs.getLong("n")));
    }

    /** Records held per homeserver and origin. */
    public record OriginCount(String homeserverId, String origin, long count) {}

    /**
     * A deterministic Merkle checkpoint over the current records: sorted leaves of
     * {@code A|<accountId>|<homeserverId>|<origin>}. The accountId is fixed length and the origin is a fixed
     * token, and the codec refuses the delimiter inside a homeserver id, so one leaf string has one reading.
     * The root depends only on the records, never on the time.
     */
    public PlacementCheckpoint checkpoint() {
        List<String> leaves = new ArrayList<>(jdbc.query(
                "SELECT account_id, homeserver_id, origin FROM placement_record",
                (rs, n) -> "A|" + rs.getString(1) + "|" + rs.getString(2) + "|" + rs.getString(3)));
        leaves.sort(String::compareTo);
        List<String> leafHashes = leaves.stream()
                .map(s -> MerkleTree.leafHash(s.getBytes(StandardCharsets.UTF_8)))
                .toList();
        return new PlacementCheckpoint(MerkleTree.root(leafHashes), leaves.size(), Instant.now());
    }

    private static LocalDateTime utc(Instant instant) {
        return instant == null ? null : LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        LocalDateTime value = rs.getObject(column, LocalDateTime.class);
        return value == null ? null : value.toInstant(ZoneOffset.UTC);
    }
}
