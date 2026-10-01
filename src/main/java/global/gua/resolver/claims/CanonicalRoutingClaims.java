package global.gua.resolver.claims;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.Collectors;

/** The bytes a claims issuer signs. Values are escaped so the encoding is injective. */
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
