package global.gua.resolver.governance.store;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import global.gua.resolver.governance.Registry;

/**
 * Persistence for accepted registry epochs: one row per registry per epoch, never updated.
 *
 * <p>The content is stored as the JSON that was hashed, not as reconstructed fields, so the epoch can be
 * re-verified later against exactly what was signed. Timestamps are stored as UTC {@link LocalDateTime}
 * rather than through the JVM's default zone, for the same reason the member attestation columns are: they
 * are signed values, and a zone change must not be able to move them and invalidate a signature.
 */
@Repository
public class RegistryEpochRepository {

    private final JdbcTemplate jdbc;

    public RegistryEpochRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * One accepted epoch as stored.
     *
     * @param contentJson    the registry content the epoch's contentHash commits to, as accepted
     * @param signaturesJson the governance signatures, which sit outside the canonical bytes
     * @param logLeafIndex   the MEMBERSHIP_EPOCH leaf that committed it
     */
    public record StoredEpoch(Registry registry, long epoch, String genesisId, String previousHash,
                              String epochHash, Instant issuedAt, String contentJson, String signaturesJson,
                              Instant acceptedAt, Long logLeafIndex) {}

    private final RowMapper<StoredEpoch> mapper = (rs, n) -> new StoredEpoch(
            Registry.of(rs.getString("registry")),
            rs.getLong("epoch"),
            rs.getString("genesis_id"),
            rs.getString("previous_hash"),
            rs.getString("epoch_hash"),
            instant(rs, "issued_at"),
            rs.getString("content_json"),
            rs.getString("signatures_json"),
            instant(rs, "accepted_at"),
            (Long) rs.getObject("log_leaf_index"));

    /** The highest accepted epoch for a registry, or empty when none has been accepted yet. */
    public Optional<StoredEpoch> findCurrent(Registry registry) {
        return jdbc.query("""
                SELECT * FROM registry_epoch WHERE registry = ? ORDER BY epoch DESC LIMIT 1
                """, mapper, registry.wireName()).stream().findFirst();
    }

    public Optional<StoredEpoch> find(Registry registry, long epoch) {
        return jdbc.query("SELECT * FROM registry_epoch WHERE registry = ? AND epoch = ?",
                mapper, registry.wireName(), epoch).stream().findFirst();
    }

    public List<StoredEpoch> history(Registry registry) {
        return jdbc.query("SELECT * FROM registry_epoch WHERE registry = ? ORDER BY epoch",
                mapper, registry.wireName());
    }

    /**
     * Insert an accepted epoch. The primary key on (registry, epoch) is what makes two concurrent
     * submissions of the same epoch number a constraint violation rather than a silent overwrite: an epoch
     * is accepted once and never rewritten.
     */
    public void insert(StoredEpoch e) {
        jdbc.update("""
                INSERT INTO registry_epoch
                    (registry, epoch, genesis_id, previous_hash, epoch_hash, issued_at, content_json,
                     signatures_json, accepted_at, log_leaf_index)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                e.registry().wireName(), e.epoch(), e.genesisId(), e.previousHash(), e.epochHash(),
                utc(e.issuedAt()), e.contentJson(), e.signaturesJson(), utc(e.acceptedAt()),
                e.logLeafIndex());
    }

    private static LocalDateTime utc(Instant instant) {
        return instant == null ? null : LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        LocalDateTime value = rs.getObject(column, LocalDateTime.class);
        return value == null ? null : value.toInstant(ZoneOffset.UTC);
    }
}
