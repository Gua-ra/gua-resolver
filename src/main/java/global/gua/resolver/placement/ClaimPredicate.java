package global.gua.resolver.placement;

import java.util.List;
import java.util.Map;

/**
 * A declarative claim attached to a homeserver's signed roster entry: "I host accounts that match this."
 *
 * <p>Because predicates live in the authority-signed roster, an operator can only claim what was admitted,
 * and the authority validates non-overlap at admission (two carriers can't claim the same range). Adding a
 * carrier/institution claim is therefore a signed-roster edit — no resolver code change, no redeploy.
 *
 * <p>All set fields are ANDed. {@code remoteClaimUrl}, when present, delegates the final yes/no to the
 * operator's own webhook (for membership logic the resolver shouldn't encode).
 *
 * @param country        match ISO country (e.g. "BR")
 * @param mccmnc         match carrier MCC+MNC (e.g. "72411" = Vivo BR)
 * @param carrier        match carrier name
 * @param phonePrefixes  match if the E.164 phone starts with any of these (e.g. ["+5511","+5519"])
 * @param affiliation    match if context affiliations contain this domain (e.g. "usp.br")
 * @param attributeMatch match if context attributes contain all these key=value pairs
 * @param remoteClaimUrl operator webhook that returns whether this user belongs to them
 * @param priority       lower wins; ties broken deterministically by homeserver id
 */
public record ClaimPredicate(
        String country,
        String mccmnc,
        String carrier,
        List<String> phonePrefixes,
        String affiliation,
        Map<String, String> attributeMatch,
        String remoteClaimUrl,
        int priority) {

    /** Pure, local evaluation (the remote webhook is handled by {@code RemoteClaimRule}). */
    public boolean matchesLocally(PlacementContext ctx) {
        if (country != null && !country.equalsIgnoreCase(ctx.country())) return false;
        if (mccmnc != null && !mccmnc.equals(ctx.mccmnc())) return false;
        if (carrier != null && (ctx.carrier() == null || !carrier.equalsIgnoreCase(ctx.carrier()))) return false;
        if (phonePrefixes != null && !phonePrefixes.isEmpty()) {
            String p = ctx.e164Phone();
            if (p == null || phonePrefixes.stream().noneMatch(p::startsWith)) return false;
        }
        if (affiliation != null && (ctx.affiliations() == null || !ctx.affiliations().contains(affiliation))) return false;
        if (attributeMatch != null) {
            for (var e : attributeMatch.entrySet()) {
                if (!e.getValue().equals(ctx.attributes().get(e.getKey()))) return false;
            }
        }
        return true;
    }

    public boolean isRemote() {
        return remoteClaimUrl != null && !remoteClaimUrl.isBlank();
    }
}
