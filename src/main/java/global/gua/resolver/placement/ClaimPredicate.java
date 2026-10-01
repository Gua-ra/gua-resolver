package global.gua.resolver.placement;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;

/** All set fields are ANDed; the lowest priority wins. */
public record ClaimPredicate(
        String country,
        String mccmnc,
        String carrier,
        List<String> phonePrefixes,
        String affiliation,
        Map<String, String> attributeMatch,
        String remoteClaimUrl,
        int priority) {

    public boolean matchesLocally(PlacementContext ctx) {
        if (country != null && !country.equalsIgnoreCase(ctx.country())) return false;
        if (mccmnc != null && !mccmnc.equals(ctx.mccmnc())) return false;
        if (carrier != null && (ctx.carrier() == null || !carrier.equalsIgnoreCase(ctx.carrier()))) return false;
        if (phonePrefixes != null && !phonePrefixes.isEmpty()) {
            String p = ctx.e164Phone();
            if (p == null || phonePrefixes.stream().noneMatch(p::startsWith)) return false;
        }
        if (affiliation != null) {
            if (!ctx.claimsVerified()) return false;
            if (ctx.affiliations() == null || !ctx.affiliations().contains(affiliation)) return false;
        }
        if (attributeMatch != null && !attributeMatch.isEmpty()) {
            if (!ctx.claimsVerified()) return false;
            Map<String, String> attrs = ctx.attributes() == null ? Map.of() : ctx.attributes();
            for (var e : attributeMatch.entrySet()) {
                if (!e.getValue().equals(attrs.get(e.getKey()))) return false;
            }
        }
        return true;
    }

    /** Derived, so not serialized: a strict reader of signed content would refuse the extra field. */
    @JsonIgnore
    public boolean isRemote() {
        return remoteClaimUrl != null && !remoteClaimUrl.isBlank();
    }
}
