package global.gua.resolver.placement;

import java.util.Map;
import java.util.Optional;

/**
 * Everything the placement rules may use to decide where a brand-new account lives. All fields are
 * optional so callers supply only what they have verified; rules abstain when their inputs are absent.
 *
 * @param e164Phone     verified phone in E.164 (e.g. +5511987654321)
 * @param country       ISO country derived from the phone (e.g. BR)
 * @param mccmnc        mobile country+network code derived from the number, if known (carrier identity)
 * @param carrier       human carrier name, if known
 * @param regionHint    explicit region/tenant hint from the caller
 * @param affiliations  verified affiliation assertions (e.g. ["usp.br"]) from an upstream IdP/claim
 * @param attributes    open-ended verified attributes for custom/remote claim rules
 */
public record PlacementContext(
        String e164Phone,
        String country,
        String mccmnc,
        String carrier,
        String regionHint,
        java.util.List<String> affiliations,
        Map<String, String> attributes) {

    /** Convenience Optional view of the phone (the record's String accessors cover the rest). */
    public Optional<String> phone() { return Optional.ofNullable(e164Phone); }

    public static PlacementContext forPhone(String e164) {
        return new PlacementContext(e164, null, null, null, null, java.util.List.of(), Map.of());
    }
}
