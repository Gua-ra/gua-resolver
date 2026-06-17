package global.gua.resolver.roster;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import global.gua.resolver.crypto.MerkleTree;

/**
 * Persistent, RFC 6962 transparency log (§5). Every membership change (admit/update/suspend/revoke/
 * authority-set change) is appended as an immutable, hash-chained leaf; the published checkpoint is the
 * Merkle root over all leaves plus the tree size. Survives restarts (rows in {@code transparency_log}) so
 * the audit trail is durable from day 0, and mirrors can prove the authority never rewrote history.
 */
@Component
public class JdbcTransparencyLog implements TransparencyLog {

    private final JdbcTemplate jdbc;

    public JdbcTransparencyLog(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    @Transactional
    public synchronized SignedRoster.LogCheckpoint append(String type, String homeserverId,
                                                          String payloadHash) {
        long index = nextIndex();
        Instant now = Instant.now();
        String leafData = index + "|" + type + "|" + (homeserverId == null ? "" : homeserverId)
                + "|" + payloadHash + "|" + now.toEpochMilli();
        String leafHash = MerkleTree.leafHash(leafData.getBytes(StandardCharsets.UTF_8));
        jdbc.update("""
                INSERT INTO transparency_log
                    (leaf_index, event_type, homeserver_id, payload_hash, leaf_hash, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, index, type, homeserverId, payloadHash, leafHash, Timestamp.from(now));
        return head();
    }

    @Override
    public SignedRoster.LogCheckpoint head() {
        List<String> leaves = leafHashes();
        return new SignedRoster.LogCheckpoint(MerkleTree.root(leaves), leaves.size());
    }

    /**
     * Authority-side consistency check: confirm {@code older} is a genuine prefix of the current log (i.e.
     * the current head extends it append-only). Computes the proof from the stored leaves and verifies it
     * against both roots — the same check a mirror performs with the proof shipped over the wire.
     */
    @Override
    public boolean verifyConsistency(SignedRoster.LogCheckpoint older, SignedRoster.LogCheckpoint newer) {
        int first = (int) older.size();
        int second = (int) newer.size();
        List<String> leaves = leafHashes();
        if (second > leaves.size() || first > second) {
            return false;
        }
        List<String> proof = MerkleTree.consistencyProof(leaves, first, second);
        return MerkleTree.verifyConsistency(first, second, older.merkleRoot(), newer.merkleRoot(), proof);
    }

    /** The consistency proof between two tree sizes, for a mirror to verify an extension over the wire. */
    public List<String> consistencyProof(int first, int second) {
        return MerkleTree.consistencyProof(leafHashes(), first, second);
    }

    public List<Event> events() {
        return jdbc.query(
                "SELECT leaf_index, event_type, homeserver_id, payload_hash, recorded_at "
                        + "FROM transparency_log ORDER BY leaf_index",
                (rs, n) -> new Event(
                        rs.getLong("leaf_index"),
                        rs.getString("event_type"),
                        rs.getString("homeserver_id"),
                        rs.getString("payload_hash"),
                        rs.getTimestamp("recorded_at").toInstant().toString()));
    }

    private List<String> leafHashes() {
        return jdbc.queryForList(
                "SELECT leaf_hash FROM transparency_log ORDER BY leaf_index", String.class);
    }

    private long nextIndex() {
        Long max = jdbc.queryForObject("SELECT MAX(leaf_index) FROM transparency_log", Long.class);
        return max == null ? 0L : max + 1L;
    }
}
