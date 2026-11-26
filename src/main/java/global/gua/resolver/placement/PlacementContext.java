package global.gua.resolver.placement;

import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * {@code affiliations} and {@code attributes} are trusted only when {@code claimsVerified}, which only the
 * routing-claims verifier may set. Nothing about the phone is verified.
 */
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

    public PlacementContext withoutUnverifiedClaims() {
        return claimsVerified ? this
                : new PlacementContext(e164Phone, country, mccmnc, carrier, regionHint, java.util.List.of(), Map.of(),
                        false);
    }

    /**
     * Must be identical on every node. Not injective, so use it only to seed bucketing, never where a
     * collision would matter.
     */
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
