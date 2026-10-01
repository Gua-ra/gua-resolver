/*
 * Copyright 2026 Gua
 */
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

/** accountId is the primary key, so a second homeserver's claim collides on insert. */
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

    public Optional<StoredPlacementRecord> find(String accountId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM placement_record WHERE account_id = ?",
                mapper, accountId).stream().findFirst();
    }

    public void insert(StoredPlacementRecord record) {
        jdbc.update("INSERT INTO placement_record (" + COLUMNS + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                record.accountId(), record.homeserverId(), record.generation(), record.origin().name(),
                utc(record.issuedAt()), utc(record.notBefore()), utc(record.notAfter()),
                record.recordB64(), record.signatureB64(), utc(record.receivedAt()));
    }

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

    public List<StoredPlacementRecord> listByHomeserver(String homeserverId, String afterAccountId,
                                                        int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM placement_record "
                        + "WHERE homeserver_id = ? AND account_id > ? ORDER BY account_id LIMIT ?",
                mapper, homeserverId, afterAccountId == null ? "" : afterAccountId, limit);
    }

    public List<StoredPlacementRecord> page(String afterAccountId, int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM placement_record "
                        + "WHERE account_id > ? ORDER BY account_id LIMIT ?",
                mapper, afterAccountId == null ? "" : afterAccountId, limit);
    }

    public long count() {
        Long n = jdbc.queryForObject("SELECT COUNT(*) FROM placement_record", Long.class);
        return n == null ? 0L : n;
    }

    public List<OriginCount> counts() {
        return jdbc.query("SELECT homeserver_id, origin, COUNT(*) AS n FROM placement_record "
                        + "GROUP BY homeserver_id, origin",
                (rs, n) -> new OriginCount(rs.getString("homeserver_id"), rs.getString("origin"),
                        rs.getLong("n")));
    }

    public record OriginCount(String homeserverId, String origin, long count) {}

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
