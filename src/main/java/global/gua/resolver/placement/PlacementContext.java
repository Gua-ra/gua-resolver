package global.gua.resolver.placement;

import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/** affiliations and attributes are trusted only when claimsVerified is true; only the verifier sets it. */
public record PlacementContext(
        String e164Phone,
        String country,
        String mccmnc,
        String carrier,
        String regionHint,
        java.util.List<String> affiliations,
        Map<String, String> attributes,
        boolean claimsVerified) {

    public Optional<String> phone() { return Optional.ofNullable(e164Phone); }

    public static PlacementContext forPhone(String e164) {
        return new PlacementContext(e164, null, null, null, null, java.util.List.of(), Map.of(), false);
    }

    /** Bucketing key for the weighted fallback hash only. Not injective: never sign or compare it. */
    public String canonicalRoutingKey() {
        StringBuilder sb = new StringBuilder();
        sb.append("phone=").append(nz(e164Phone)).append('\n');
        sb.append("country=").append(nz(country)).append('\n');
        sb.append("mccmnc=").append(nz(mccmnc)).append('\n');
        sb.append("carrier=").append(nz(carrier)).append('\n');
        sb.append("region=").append(nz(regionHint)).append('\n');
        sb.append("affiliations=");
        if (affiliations != null) {
            sb.append(affiliations.stream().sorted().reduce((a, b) -> a + "|" + b).orElse(""));
        }
        sb.append('\n');
        sb.append("attrs=");
        if (attributes != null) {
            new TreeMap<>(attributes).forEach((k, v) -> sb.append(k).append('=').append(v).append('|'));
        }
        return sb.toString();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
