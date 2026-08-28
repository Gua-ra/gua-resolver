package global.gua.resolver.claims;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Produces the exact bytes a MAS / identity-service issuer signs over a routing-claims envelope (and that the
 * resolver re-derives to verify the signature). The format is one {@code key=value} line per field, in a
 * fixed order, prefixed by a version tag.
 *
 * <p>It is deliberately <b>injective</b>: {@link #escape} backslash-escapes the structural delimiters
 * ({@code \n}, {@code |}, {@code =}) inside every value, so two different logical claim sets can never produce
 * the same bytes. Without that, e.g. {@code {"a":"b|c=d"}} and {@code {"a":"b","c":"d"}} would encode
 * identically, and one signature would cover a claim set the issuer never asserted.
 */
public final class CanonicalRoutingClaims {

    private CanonicalRoutingClaims() {}

    public static byte[] bytes(RoutingClaimsEnvelope envelope) {
        String canonical = "gua-routing-claims.v1\n"
                + "schema=" + escape(envelope.schemaVersion()) + "\n"
                + "issuer=" + escape(envelope.issuer()) + "\n"
                + "audience=" + escape(envelope.audience()) + "\n"
                + "issuedAt=" + epochMillis(envelope.issuedAt()) + "\n"
                + "expiresAt=" + epochMillis(envelope.expiresAt()) + "\n"
                + "nonce=" + escape(envelope.nonce()) + "\n"
                + "subject=" + escape(envelope.subject()) + "\n"
                + "affiliations=" + affiliations(envelope.affiliations()) + "\n"
                + "attrs=" + attributes(envelope.attributes()) + "\n";
        return canonical.getBytes(StandardCharsets.UTF_8);
    }

    /** Affiliations sorted for a stable order, each escaped, joined by {@code |}. Null entries are dropped
     *  (the verifier rejects them upstream; this keeps the signer path from NPE-ing on malformed input). */
    private static String affiliations(List<String> affiliations) {
        if (affiliations == null) {
            return "";
        }
        return affiliations.stream()
                .filter(Objects::nonNull)
                .sorted()
                .map(CanonicalRoutingClaims::escape)
                .collect(Collectors.joining("|"));
    }

    /** Attributes sorted by key (TreeMap), each {@code key=value} escaped, joined by {@code |}. */
    private static String attributes(Map<String, String> attributes) {
        if (attributes == null) {
            return "";
        }
        return new TreeMap<>(attributes).entrySet().stream()
                .filter(entry -> entry.getKey() != null && entry.getValue() != null)
                .map(entry -> escape(entry.getKey()) + "=" + escape(entry.getValue()))
                .collect(Collectors.joining("|"));
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder escaped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '\n' || c == '|' || c == '=') {
                escaped.append('\\');
            }
            escaped.append(c);
        }
        return escaped.toString();
    }

    private static long epochMillis(Instant instant) {
        return instant == null ? 0L : instant.toEpochMilli();
    }
}
