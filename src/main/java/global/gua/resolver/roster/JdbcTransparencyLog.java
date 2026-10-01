package global.gua.resolver.roster;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import global.gua.resolver.crypto.MerkleTree;

/**
 * Persistent, RFC 6962 transparency log (§5). Every membership change (admit/update/suspend/revoke/
 * authority-set change) is appended as an immutable, hash-chained leaf; the published checkpoint is the
 * Merkle root over all leaves plus the tree size. Survives restarts (rows in {@code transparency_log}) so
 * the audit trail is durable from day 0, and a mirror can detect history rewritten since its own last
 * checkpoint. That is detection, not prevention: it does not rule out two readers being served different
 * views (ADM-001 L11, L12).
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
                                                          String payloadHash, Instant recordedAt) {
        long index = nextIndex();
        Instant now = recordedAt == null ? Instant.now() : recordedAt;
        // One definition of the preimage, shared with every verifier that recomputes a leaf.
        String leafHash = TransparencyLeaf.hash(index, type, homeserverId, payloadHash, now.toEpochMilli());
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
     * against both roots, the same check a mirror performs with the proof shipped over the wire.
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

    /**
     * The RFC 6962 audit path for one leaf, computed against a tree of exactly {@code treeSize} leaves.
     *
     * <p>The size is a parameter rather than the current head on purpose: the root a reader holds is the one
     * inside the signed roster's canonical bytes, and the log may have grown since that roster was built. A
     * proof computed at the current head would then verify against nothing the reader can authenticate. The
     * caller passes the size of the checkpoint it is going to serve alongside the proof.
     */
    public List<String> inclusionProof(long leafIndex, int treeSize) {
        List<String> leaves = leafHashes();
        if (treeSize < 0 || treeSize > leaves.size() || leafIndex < 0 || leafIndex >= treeSize) {
            throw new IllegalArgumentException("leaf index outside the checkpoint");
        }
        return MerkleTree.inclusionProof(leaves.subList(0, treeSize), (int) leafIndex);
    }

    /**
     * One leaf by index, carrying the sequenced time as epoch milliseconds and the stored leaf hash.
     *
     * <p>{@link Event} serves {@code recordedAt} as an ISO-8601 string, which is not what the leaf preimage
     * hashes over, so a caller that has to recompute a leaf hash reads it here instead of converting a
     * formatted timestamp back (TransparencyLeaf).
     */
    public Optional<Leaf> leaf(long index) {
        return jdbc.query(
                "SELECT leaf_index, event_type, homeserver_id, payload_hash, leaf_hash, recorded_at "
                        + "FROM transparency_log WHERE leaf_index = ?",
                (rs, n) -> new Leaf(
                        rs.getLong("leaf_index"),
                        rs.getString("event_type"),
                        rs.getString("homeserver_id"),
                        rs.getString("payload_hash"),
                        rs.getString("leaf_hash"),
                        rs.getTimestamp("recorded_at").toInstant().toEpochMilli()),
                index).stream().findFirst();
    }

    /** The index of the first leaf of this type with this payload hash, so an append stays idempotent. */
    public Optional<Long> findLeafIndex(String type, String payloadHash) {
        return jdbc.queryForList(
                "SELECT leaf_index FROM transparency_log WHERE event_type = ? AND payload_hash = ? "
                        + "ORDER BY leaf_index",
                Long.class, type, payloadHash).stream().findFirst();
    }

    /** A leaf as a verifier needs it: every field of its preimage, plus the hash the tree was built with. */
    public record Leaf(long index, String type, String homeserverId, String payloadHash, String leafHash,
                       long recordedAtMillis) {}

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

    /** True if a leaf of this type with this payload hash already exists (so policy versions log once). */
    public boolean hasLeaf(String type, String payloadHash) {
        Integer n = jdbc.queryForObject(
                "SELECT COUNT(*) FROM transparency_log WHERE event_type = ? AND payload_hash = ?",
                Integer.class, type, payloadHash);
        return n != null && n > 0;
    }

    /** Events of a single type (e.g. POLICY_PUBLISH), for the policy-log audit view. */
    public List<Event> eventsOfType(String type) {
        return events().stream().filter(e -> type.equals(e.type())).toList();
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
