package global.gua.resolver.placement;

import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Everything the placement rules may use to decide where a brand-new account lives. All fields are
 * optional so callers supply only what they have verified; rules abstain when their inputs are absent.
 *
 * @param e164Phone     phone in E.164 (e.g. +5511987654321); the resolver verifies nothing about it (ADM-001 L16)
 * @param country       ISO country derived from the phone (e.g. BR)
 * @param mccmnc        mobile country+network code derived from the number, if known (carrier identity)
 * @param carrier       human carrier name, if known
 * @param regionHint    explicit region/tenant hint from the caller
 * @param affiliations  affiliation assertions (e.g. ["usp.br"]); trusted for institution/OIDC routing
 *                      only when {@code claimsVerified} is true (i.e. they came from a verified envelope)
 * @param attributes    open-ended attributes for custom/remote claim rules; same trust rule as affiliations
 * @param claimsVerified whether {@code affiliations}/{@code attributes} arrived inside a signature-verified
 *                       routing-claims envelope. Institution/OIDC placement requires this to be true; it is
 *                       set only by the verifier path and can never be self-asserted by a public caller.
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

    /** Convenience Optional view of the phone (the record's String accessors cover the rest). */
    public Optional<String> phone() { return Optional.ofNullable(e164Phone); }

    public static PlacementContext forPhone(String e164) {
        return new PlacementContext(e164, null, null, null, null, java.util.List.of(), Map.of(), false);
    }

    /**
     * A stable, deterministic key that seeds the weighted-fallback bucketing hash so all nodes place the same
     * context identically. This is intentionally a plain (non-injective) bucketing key, NOT a signed/canonical
     * form: it feeds only a distribution hash, never a signature, so unescaped delimiters here are harmless.
     * Do not reuse it anywhere a collision would matter; use the escaped {@code Canonical*} encoders instead.
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
