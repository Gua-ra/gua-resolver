package global.gua.resolver.directory;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import global.gua.resolver.crypto.MerkleTree;

/**
 * JDBC-backed {@link DirectoryStore} over the {@code directory_entry} / {@code username_index} tables
 * (Postgres in prod, H2 in tests). Phones are stored only as peppered HMACs. Upserts are portable
 * (UPDATE-then-INSERT, no vendor-specific {@code ON CONFLICT}/{@code MERGE}).
 *
 * <p>Authority mode only — it owns the phone graph. Mirrors {@link RemoteDirectoryStore query} it instead
 * of replicating it (§4).
 */
@Component
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class JdbcDirectoryStore implements DirectoryStore {

    private final JdbcTemplate jdbc;
    private final PhoneHasher hasher;

    public JdbcDirectoryStore(JdbcTemplate jdbc, PhoneHasher hasher) {
        this.jdbc = jdbc;
        this.hasher = hasher;
    }

    @Override
    public Optional<String> homeserverIdForPhone(String e164Phone) {
        return homeserverIdForPhoneHash(hasher.hashPhone(e164Phone));
    }

    @Override
    public Optional<String> homeserverIdForPhoneHash(String phoneHash) {
        return jdbc.query(
                "SELECT homeserver_id FROM directory_entry WHERE phone_hash = ?",
                (rs, n) -> rs.getString(1), phoneHash).stream().findFirst();
    }

    @Override
    public Optional<String> homeserverIdForUsername(String username) {
        return jdbc.query(
                "SELECT homeserver_id FROM username_index WHERE username = ?",
                (rs, n) -> rs.getString(1), normalize(username)).stream().findFirst();
    }

    @Override
    public void putPhone(String e164Phone, String homeserverId) {
        upsert("directory_entry", "phone_hash", hasher.hashPhone(e164Phone), homeserverId);
    }

    @Override
    public void putUsername(String username, String homeserverId) {
        upsert("username_index", "username", normalize(username), homeserverId);
    }

    @Override
    public void removePhone(String e164Phone) {
        jdbc.update("DELETE FROM directory_entry WHERE phone_hash = ?", hasher.hashPhone(e164Phone));
    }

    /**
     * A deterministic Merkle checkpoint over the current directory: sorted leaves of
     * {@code P|<phoneHash>|<hsId>} and {@code U|<username>|<hsId>}. The root depends only on the entries
     * (not the time), so the same directory always produces the same root; the raw phone graph never leaves.
     */
    public DirectoryCheckpoint checkpoint() {
        List<String> leaves = new ArrayList<>();
        leaves.addAll(jdbc.query("SELECT phone_hash, homeserver_id FROM directory_entry",
                (rs, n) -> "P|" + rs.getString(1) + "|" + rs.getString(2)));
        leaves.addAll(jdbc.query("SELECT username, homeserver_id FROM username_index",
                (rs, n) -> "U|" + rs.getString(1) + "|" + rs.getString(2)));
        leaves.sort(String::compareTo);
        List<String> leafHashes = leaves.stream()
                .map(s -> MerkleTree.leafHash(s.getBytes(StandardCharsets.UTF_8)))
                .toList();
        return new DirectoryCheckpoint(MerkleTree.root(leafHashes), leaves.size(), Instant.now());
    }

    private void upsert(String table, String keyCol, String key, String homeserverId) {
        Timestamp now = Timestamp.from(Instant.now());
        int updated = jdbc.update(
                "UPDATE " + table + " SET homeserver_id = ?, updated_at = ? WHERE " + keyCol + " = ?",
                homeserverId, now, key);
        if (updated == 0) {
            jdbc.update(
                    "INSERT INTO " + table + " (" + keyCol + ", homeserver_id, updated_at) VALUES (?, ?, ?)",
                    key, homeserverId, now);
        }
    }

    private static String normalize(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("username required");
        }
        return username.trim().toLowerCase(Locale.ROOT);
    }
}
