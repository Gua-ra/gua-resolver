package global.gua.resolver.claims;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.TreeMap;

/**
 * Deterministic bytes signed by MAS / identity-service routing-claims issuers.
 *
 * <p>The encoding is <b>injective</b>: every string value is escaped so the structural delimiters
 * ({@code \n}, {@code |}, {@code =}) cannot appear literally inside a value. Without this, two different
 * logical claim sets could produce identical signed bytes (e.g. {@code {"a":"b|c=d"}} vs
 * {@code {"a":"b","c":"d"}}), letting one signature cover a claim set the issuer never asserted.
 */
public final class CanonicalRoutingClaims {

    private CanonicalRoutingClaims() {}

    public static byte[] bytes(RoutingClaimsEnvelope envelope) {
        StringBuilder sb = new StringBuilder();
        sb.append("gua-routing-claims.v1\n");
        sb.append("schema=").append(esc(envelope.schemaVersion())).append('\n');
        sb.append("issuer=").append(esc(envelope.issuer())).append('\n');
        sb.append("audience=").append(esc(envelope.audience())).append('\n');
        sb.append("issuedAt=").append(epoch(envelope.issuedAt())).append('\n');
        sb.append("expiresAt=").append(epoch(envelope.expiresAt())).append('\n');
        sb.append("nonce=").append(esc(envelope.nonce())).append('\n');
        sb.append("subject=").append(esc(envelope.subject())).append('\n');
        sb.append("affiliations=").append(affiliations(envelope.affiliations())).append('\n');
        sb.append("attrs=").append(attrs(envelope.attributes())).append('\n');
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String affiliations(List<String> affiliations) {
        if (affiliations == null || affiliations.isEmpty()) {
            return "";
        }
        return affiliations.stream().sorted().map(CanonicalRoutingClaims::esc)
                .reduce((a, b) -> a + "|" + b).orElse("");
    }

    private static String attrs(Map<String, String> attributes) {
        if (attributes == null || attributes.isEmpty()) {
            return "";
        }
        StringJoiner j = new StringJoiner("|");
        new TreeMap<>(attributes).forEach((k, v) -> j.add(esc(k) + "=" + esc(v)));
        return j.toString();
    }

    /** Backslash-escape the structural delimiters so the encoding is unambiguous (injective). */
    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '\n' || c == '|' || c == '=') {
                b.append('\\');
            }
            b.append(c);
        }
        return b.toString();
    }

    private static long epoch(Instant instant) {
        return instant == null ? 0L : instant.toEpochMilli();
    }
}
