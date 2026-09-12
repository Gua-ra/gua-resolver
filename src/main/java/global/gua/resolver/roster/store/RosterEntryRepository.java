package global.gua.resolver.roster.store;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.roster.CanonicalMemberEntry;
import global.gua.resolver.roster.MemberAttestation;
import global.gua.resolver.roster.MemberSignature;
import global.gua.resolver.roster.RosterEntry;

/**
 * Persistence for admitted homeservers: the roster the node signs and serves in AUTHORITY mode. Claim
 * predicates are stored as JSON. Authority mode reads + writes this; mirrors never touch it (they pull the
 * signed snapshot).
 *
 * <p>An entry also carries the member's accepted self-signature (ADM-007): the attestation columns, the
 * genesis key the operator was admitted with, and one {@code roster_member_history} row per accepted
 * attestation. The attestation timestamps are stored as UTC {@link LocalDateTime}, not through the JVM's
 * default zone, because they are signed values: a zone change or a daylight-saving fold must not be able to
 * move them and invalidate the signature.
 */
@Repository
public class RosterEntryRepository {

    private final JdbcTemplate jdbc;
    private final ObjectMapper json;

    public RosterEntryRepository(JdbcTemplate jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    private final RowMapper<RosterEntry> mapper = (rs, n) -> {
        Homeserver hs = new Homeserver(
                rs.getString("id"),
                rs.getString("server_name"),
                rs.getString("base_url"),
                rs.getString("mas_issuer"),
                rs.getString("region"),
                rs.getInt("weight"),
                rs.getBoolean("accepts_new"),
                rs.getString("signing_key"),
                Homeserver.SearchVisibility.valueOf(rs.getString("search_visibility")),
                readGroups(rs.getString("search_groups_json")));
        return new RosterEntry(hs, readClaims(rs.getString("claims_json")),
                rs.getTimestamp("admitted_at").toInstant(),
                RosterEntry.Status.valueOf(rs.getString("status")),
                readMember(rs));
    };

    /** One accepted attestation, kept so the sequence chain and each rotation stay auditable. */
    public record MemberHistoryRow(String homeserverId, long sequence, String keyId, String signingKey,
                                   String entryJson, String entryHash, List<MemberSignature> signatures,
                                   Instant acceptedAt, Long logLeafIndex) {}

    /**
     * What a governance epoch needs to see about an entry: its current status, any status change recorded
     * as intent but not yet ratified, the hash of the member's own signed entry, and the placement
     * attributes the epoch takes over (ADM-001 L10).
     *
     * @param pendingStatus  a requested status awaiting a governance epoch, or null
     * @param registryEpoch  the epoch that set the current status, or null when it predates governance
     */
    public record GovernanceRow(String homeserverId, RosterEntry.Status status,
                                RosterEntry.Status pendingStatus, String memberEntryHash, int weight,
                                boolean acceptsNew, List<ClaimPredicate> claims, Long registryEpoch) {}

    public List<RosterEntry> findAll() {
        return jdbc.query("SELECT * FROM roster_entry ORDER BY id", mapper);
    }

    public Optional<RosterEntry> findById(String id) {
        return jdbc.query("SELECT * FROM roster_entry WHERE id = ?", mapper, id).stream().findFirst();
    }

    public boolean existsByServerName(String serverName) {
        Integer c = jdbc.queryForObject(
                "SELECT COUNT(*) FROM roster_entry WHERE server_name = ?", Integer.class, serverName);
        return c != null && c > 0;
    }

    public long count() {
        Long c = jdbc.queryForObject("SELECT COUNT(*) FROM roster_entry", Long.class);
        return c == null ? 0 : c;
    }

    /** Insert an entry whose genesis key is its current signing key and whose possession proof is not kept. */
    public void insert(RosterEntry e) {
        insert(e, e.homeserver().signingKey(), null, null);
    }

    /**
     * @param genesisSigningKey the key the operator was admitted with, retained as the anchor of its
     *                          attestation chain
     * @param genesisKeyProof   the legacy possession signature over {@code server_name}, or null when the
     *                          applicant proved possession by signing its own entry instead
     * @param memberEntryHash   SHA-256 of the accepted entry's canonical bytes, or null when unattested
     */
    public void insert(RosterEntry e, String genesisSigningKey, String genesisKeyProof,
                       String memberEntryHash) {
        Homeserver h = e.homeserver();
        MemberAttestation m = e.member();
        jdbc.update("""
                INSERT INTO roster_entry
                    (id, server_name, base_url, mas_issuer, region, weight, accepts_new, signing_key,
                     search_visibility, search_groups_json, claims_json, admitted_at, status,
                     member_key_id, member_sequence, member_not_before, member_not_after,
                     member_signatures_json, member_entry_hash, genesis_signing_key, genesis_key_proof)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                h.id(), h.serverName(), h.baseUrl(), h.masIssuer(), h.region(), h.weight(),
                h.acceptsNew(), h.signingKey(), h.searchVisibility().name(), writeGroups(h.searchGroups()),
                writeClaims(e.claims()),
                Timestamp.from(e.admittedAt() == null ? Instant.now() : e.admittedAt()), e.status().name(),
                m == null ? null : m.keyId(),
                m == null ? null : m.sequence(),
                m == null ? null : utc(m.notBefore()),
                m == null ? null : utc(m.notAfter()),
                m == null ? null : writeSignatures(m.signatures()),
                memberEntryHash,
                genesisSigningKey, genesisKeyProof);
    }

    public void updateStatus(String id, RosterEntry.Status status) {
        jdbc.update("UPDATE roster_entry SET status = ? WHERE id = ?", status.name(), id);
    }

    /** Every entry as a governance epoch sees it, ordered so the built content is byte-stable. */
    public List<GovernanceRow> governanceRows() {
        return jdbc.query("SELECT * FROM roster_entry ORDER BY id", (rs, n) -> {
            String pending = rs.getString("pending_status");
            return new GovernanceRow(
                    rs.getString("id"),
                    RosterEntry.Status.valueOf(rs.getString("status")),
                    pending == null ? null : RosterEntry.Status.valueOf(pending),
                    rs.getString("member_entry_hash"),
                    rs.getInt("weight"),
                    rs.getBoolean("accepts_new"),
                    readClaims(rs.getString("claims_json")),
                    (Long) rs.getObject("registry_epoch"));
        });
    }

    /**
     * Record a requested status without changing the served one. This is what "intent only" means under
     * governance: the operational key can ask, and only an epoch can act, so the operational key alone can
     * no longer take a member out of service.
     */
    public void setPendingStatus(String id, RosterEntry.Status status) {
        jdbc.update("UPDATE roster_entry SET pending_status = ? WHERE id = ?", status.name(), id);
    }

    /**
     * Apply one member of an accepted governance epoch: the status and the placement attributes the epoch
     * carries, the epoch that set them, and the intent cleared because it has now been ratified or refused.
     */
    public int applyGovernedStatus(String id, RosterEntry.Status status, int weight, boolean acceptsNew,
                                   List<ClaimPredicate> claims, long epoch) {
        return jdbc.update("""
                UPDATE roster_entry SET
                    status = ?, weight = ?, accepts_new = ?, claims_json = ?, registry_epoch = ?,
                    pending_status = NULL
                WHERE id = ?
                """, status.name(), weight, acceptsNew, writeClaims(claims), epoch, id);
    }

    /**
     * Replace the member-controlled columns with the accepted, signed values and record the attestation.
     * Only the fields the member signs are written here; weight, acceptsNew, claims and status stay as the
     * authority holds them (ADM-007).
     *
     * <p>The write is conditional on the entry still carrying {@code expectedSequence}, the accepted
     * sequence the caller verified this attestation against. A plain read-check-write does not serialise
     * at READ COMMITTED: two concurrent attestations carrying different sequences can both pass the
     * caller's check and both commit, leaving the lower sequence last and regressing the served entry. A
     * mirror that already accepted the higher sequence reads that regression as tampering and, with the
     * transition flag on, drops the homeserver from its routing view. Zero rows updated means the entry
     * moved underneath the check, so the attestation is refused rather than applied over the winner.
     *
     * @param expectedSequence the accepted sequence the attestation was verified against; 0 for an entry
     *                         that carries no member block yet
     * @return rows updated: 1 when accepted, 0 when another attestation won the race
     */
    public int updateMember(String id, Homeserver attested, MemberAttestation member, String entryHash,
                            long expectedSequence) {
        return jdbc.update("""
                UPDATE roster_entry SET
                    base_url = ?, mas_issuer = ?, region = ?, search_visibility = ?, search_groups_json = ?,
                    signing_key = ?, member_key_id = ?, member_sequence = ?, member_not_before = ?,
                    member_not_after = ?, member_signatures_json = ?, member_entry_hash = ?
                WHERE id = ? AND (member_sequence IS NULL OR member_sequence = ?)
                """,
                attested.baseUrl(), attested.masIssuer(), attested.region(),
                attested.searchVisibility().name(), writeGroups(attested.searchGroups()),
                attested.signingKey(), member.keyId(), member.sequence(), utc(member.notBefore()),
                utc(member.notAfter()), writeSignatures(member.signatures()), entryHash, id,
                expectedSequence);
    }

    public void insertMemberHistory(String homeserverId, MemberAttestation member, String signingKey,
                                    String entryJson, String entryHash, Instant acceptedAt,
                                    Long logLeafIndex) {
        jdbc.update("""
                INSERT INTO roster_member_history
                    (homeserver_id, sequence, key_id, signing_key, entry_json, entry_hash, signatures_json,
                     accepted_at, log_leaf_index)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                homeserverId, member.sequence(), member.keyId(), signingKey, entryJson, entryHash,
                writeSignatures(member.signatures()), utc(acceptedAt), logLeafIndex);
    }

    public List<MemberHistoryRow> memberHistory(String homeserverId) {
        return jdbc.query("""
                SELECT * FROM roster_member_history WHERE homeserver_id = ? ORDER BY sequence
                """, (rs, n) -> new MemberHistoryRow(
                        rs.getString("homeserver_id"),
                        rs.getLong("sequence"),
                        rs.getString("key_id"),
                        rs.getString("signing_key"),
                        rs.getString("entry_json"),
                        rs.getString("entry_hash"),
                        readSignatures(rs.getString("signatures_json")),
                        instant(rs, "accepted_at"),
                        (Long) rs.getObject("log_leaf_index")),
                homeserverId);
    }

    /** The canonical hash stored with the current attestation, for a drift check against the live entry. */
    public Optional<String> memberEntryHash(String id) {
        return jdbc.query("SELECT member_entry_hash FROM roster_entry WHERE id = ?",
                        (rs, n) -> rs.getString("member_entry_hash"), id)
                .stream().filter(java.util.Objects::nonNull).findFirst();
    }

    private MemberAttestation readMember(ResultSet rs) throws SQLException {
        String keyId = rs.getString("member_key_id");
        if (keyId == null) {
            return null;
        }
        return new MemberAttestation(CanonicalMemberEntry.SCHEMA, CanonicalMemberEntry.ALG, keyId,
                rs.getLong("member_sequence"), instant(rs, "member_not_before"),
                instant(rs, "member_not_after"), readSignatures(rs.getString("member_signatures_json")));
    }

    private static LocalDateTime utc(Instant instant) {
        return instant == null ? null : LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        LocalDateTime value = rs.getObject(column, LocalDateTime.class);
        return value == null ? null : value.toInstant(ZoneOffset.UTC);
    }

    private List<MemberSignature> readSignatures(String s) {
        try {
            return (s == null || s.isBlank())
                    ? List.of()
                    : json.readValue(s, new TypeReference<List<MemberSignature>>() {});
        } catch (Exception e) {
            throw new IllegalStateException("corrupt member_signatures_json", e);
        }
    }

    private String writeSignatures(List<MemberSignature> signatures) {
        try {
            return json.writeValueAsString(signatures == null ? List.of() : signatures);
        } catch (Exception e) {
            throw new IllegalStateException("cannot serialise member signatures", e);
        }
    }

    private List<String> readGroups(String s) {
        try {
            return (s == null || s.isBlank())
                    ? List.of()
                    : json.readValue(s, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            throw new IllegalStateException("corrupt search_groups_json", e);
        }
    }

    private String writeGroups(List<String> groups) {
        try {
            return json.writeValueAsString(groups == null ? List.of() : groups);
        } catch (Exception e) {
            throw new IllegalStateException("cannot serialise search groups", e);
        }
    }

    private List<ClaimPredicate> readClaims(String s) {
        try {
            return (s == null || s.isBlank())
                    ? List.of()
                    : json.readValue(s, new TypeReference<List<ClaimPredicate>>() {});
        } catch (Exception e) {
            throw new IllegalStateException("corrupt claims_json", e);
        }
    }

    private String writeClaims(List<ClaimPredicate> claims) {
        try {
            return json.writeValueAsString(claims == null ? List.of() : claims);
        } catch (Exception e) {
            throw new IllegalStateException("cannot serialise claims", e);
        }
    }
}
