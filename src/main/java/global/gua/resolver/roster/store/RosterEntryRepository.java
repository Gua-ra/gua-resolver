package global.gua.resolver.roster.store;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.roster.RosterEntry;

/**
 * Persistence for admitted homeservers (the authority's source-of-truth roster). Claim predicates are
 * stored as JSON. Authority mode reads + writes this; mirrors never touch it (they pull the signed snapshot).
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
                rs.getString("signing_key"));
        return new RosterEntry(hs, readClaims(rs.getString("claims_json")),
                rs.getTimestamp("admitted_at").toInstant(),
                RosterEntry.Status.valueOf(rs.getString("status")));
    };

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

    public void insert(RosterEntry e) {
        Homeserver h = e.homeserver();
        jdbc.update("""
                INSERT INTO roster_entry
                    (id, server_name, base_url, mas_issuer, region, weight, accepts_new, signing_key,
                     claims_json, admitted_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                h.id(), h.serverName(), h.baseUrl(), h.masIssuer(), h.region(), h.weight(),
                h.acceptsNew(), h.signingKey(), writeClaims(e.claims()),
                Timestamp.from(e.admittedAt() == null ? Instant.now() : e.admittedAt()), e.status().name());
    }

    public void updateStatus(String id, RosterEntry.Status status) {
        jdbc.update("UPDATE roster_entry SET status = ? WHERE id = ?", status.name(), id);
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
