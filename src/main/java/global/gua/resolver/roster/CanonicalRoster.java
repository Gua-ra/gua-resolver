package global.gua.resolver.roster;

import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.TreeMap;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.ClaimPredicate;

/**
 * Deterministic, canonical byte serialization of a roster snapshot — the exact bytes the directory
 * authorities sign and that every verifier (including third-party mirrors) reconstructs to check the
 * signatures. Covers everything EXCEPT the signatures themselves. Entries are sorted by id and all
 * collections are emitted in a fixed order, so the same logical roster always yields identical bytes on
 * any machine/JVM.
 */
public final class CanonicalRoster {

    private CanonicalRoster() {}

    /** Canonical bytes over (version, issuedAt, logCheckpoint, sorted entries). Excludes signatures. */
    public static byte[] bytes(long version, long issuedAtEpochMs, SignedRoster.LogCheckpoint checkpoint,
                               List<RosterEntry> entries) {
        StringBuilder sb = new StringBuilder();
        sb.append("gua-roster.v1\n");
        sb.append("version=").append(version).append('\n');
        sb.append("issuedAt=").append(issuedAtEpochMs).append('\n');
        sb.append("log=").append(checkpoint.merkleRoot()).append(':').append(checkpoint.size()).append('\n');
        entries.stream()
                .sorted(Comparator.comparing(e -> e.homeserver().id()))
                .forEach(e -> sb.append(entry(e)).append('\n'));
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] bytes(SignedRoster roster) {
        return bytes(roster.version(), roster.issuedAt().toEpochMilli(), roster.logCheckpoint(),
                roster.entries());
    }

    private static String entry(RosterEntry e) {
        Homeserver h = e.homeserver();
        StringJoiner j = new StringJoiner("");  // unit separator — can't appear in the fields
        j.add(h.id());
        j.add(h.serverName());
        j.add(h.baseUrl());
        j.add(h.masIssuer());
        j.add(nz(h.region()));
        j.add(Integer.toString(h.weight()));
        j.add(Boolean.toString(h.acceptsNew()));
        j.add(nz(h.signingKey()));
        j.add(e.admittedAt() == null ? "" : Long.toString(e.admittedAt().toEpochMilli()));
        j.add(e.status().name());
        j.add(claims(e.claims()));
        return j.toString();
    }

    private static String claims(List<ClaimPredicate> claims) {
        if (claims == null || claims.isEmpty()) {
            return "[]";
        }
        return claims.stream()
                .sorted(Comparator.comparingInt(ClaimPredicate::priority)
                        .thenComparing(c -> nz(c.country()))
                        .thenComparing(c -> nz(c.mccmnc()))
                        .thenComparing(c -> nz(c.affiliation())))
                .map(CanonicalRoster::claim)
                .reduce((a, b) -> a + ";" + b)
                .orElse("[]");
    }

    private static String claim(ClaimPredicate c) {
        StringJoiner j = new StringJoiner(",");
        j.add("country=" + nz(c.country()));
        j.add("mccmnc=" + nz(c.mccmnc()));
        j.add("carrier=" + nz(c.carrier()));
        j.add("prefixes=" + (c.phonePrefixes() == null ? ""
                : c.phonePrefixes().stream().sorted().reduce((a, b) -> a + "|" + b).orElse("")));
        j.add("affiliation=" + nz(c.affiliation()));
        j.add("attrs=" + attrs(c.attributeMatch()));
        j.add("remote=" + nz(c.remoteClaimUrl()));
        j.add("priority=" + c.priority());
        return j.toString();
    }

    private static String attrs(Map<String, String> m) {
        if (m == null || m.isEmpty()) {
            return "";
        }
        StringJoiner j = new StringJoiner("|");
        new TreeMap<>(m).forEach((k, v) -> j.add(k + "=" + v));
        return j.toString();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
