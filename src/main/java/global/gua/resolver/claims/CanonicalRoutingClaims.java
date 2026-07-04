package global.gua.resolver.claims;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.TreeMap;

/** Deterministic bytes signed by MAS / identity-service routing-claims issuers. */
public final class CanonicalRoutingClaims {

    private CanonicalRoutingClaims() {}

    public static byte[] bytes(RoutingClaimsEnvelope envelope) {
        StringBuilder sb = new StringBuilder();
        sb.append("gua-routing-claims.v1\n");
        sb.append("schema=").append(nz(envelope.schemaVersion())).append('\n');
        sb.append("issuer=").append(nz(envelope.issuer())).append('\n');
        sb.append("audience=").append(nz(envelope.audience())).append('\n');
        sb.append("issuedAt=").append(epoch(envelope.issuedAt())).append('\n');
        sb.append("expiresAt=").append(epoch(envelope.expiresAt())).append('\n');
        sb.append("nonce=").append(nz(envelope.nonce())).append('\n');
        sb.append("affiliations=").append(affiliations(envelope.affiliations())).append('\n');
        sb.append("attrs=").append(attrs(envelope.attributes())).append('\n');
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String affiliations(List<String> affiliations) {
        if (affiliations == null || affiliations.isEmpty()) {
            return "";
        }
        return affiliations.stream().sorted().reduce((a, b) -> a + "|" + b).orElse("");
    }

    private static String attrs(Map<String, String> attributes) {
        if (attributes == null || attributes.isEmpty()) {
            return "";
        }
        StringJoiner j = new StringJoiner("|");
        new TreeMap<>(attributes).forEach((k, v) -> j.add(k + "=" + v));
        return j.toString();
    }

    private static long epoch(Instant instant) {
        return instant == null ? 0L : instant.toEpochMilli();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
