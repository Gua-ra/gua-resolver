package global.gua.resolver.admission;

import java.util.List;

import global.gua.resolver.placement.ClaimPredicate;

/**
 * Non-overlap validation for placement claims (§6): the authority must never admit two homeservers that
 * claim the same accounts, or placement becomes ambiguous and an operator could hijack another's range.
 * Two predicates conflict when they could match the same signup — same carrier (MCCMNC or name), nested
 * phone prefixes, same affiliation domain, or an unqualified same-country claim.
 */
public final class ClaimOverlap {

    private ClaimOverlap() {}

    /** True if any predicate in {@code candidate} conflicts with any already-admitted predicate. */
    public static boolean conflicts(List<ClaimPredicate> candidate, List<ClaimPredicate> existing) {
        for (ClaimPredicate a : candidate) {
            for (ClaimPredicate b : existing) {
                if (conflicts(a, b)) {
                    return true;
                }
            }
        }
        return false;
    }

    static boolean conflicts(ClaimPredicate a, ClaimPredicate b) {
        if (eq(a.mccmnc(), b.mccmnc())) return true;
        if (eqIgnoreCase(a.carrier(), b.carrier())) return true;
        if (eqIgnoreCase(a.affiliation(), b.affiliation())) return true;
        if (prefixesOverlap(a.phonePrefixes(), b.phonePrefixes())) return true;
        // An unqualified country claim (no narrower discriminator) collides with another claim in the same
        // country, since both would match the same numbers.
        return eqIgnoreCase(a.country(), b.country())
                && unqualified(a) && unqualified(b);
    }

    private static boolean unqualified(ClaimPredicate c) {
        return c.mccmnc() == null && c.carrier() == null && c.affiliation() == null
                && (c.phonePrefixes() == null || c.phonePrefixes().isEmpty());
    }

    private static boolean prefixesOverlap(List<String> as, List<String> bs) {
        if (as == null || bs == null) return false;
        for (String a : as) {
            for (String b : bs) {
                if (a.startsWith(b) || b.startsWith(a)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean eq(String a, String b) {
        return a != null && a.equals(b);
    }

    private static boolean eqIgnoreCase(String a, String b) {
        return a != null && a.equalsIgnoreCase(b);
    }
}
