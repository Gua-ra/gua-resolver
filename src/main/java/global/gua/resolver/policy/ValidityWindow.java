package global.gua.resolver.policy;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

final class ValidityWindow {

    private ValidityWindow() {}

    static boolean contains(Instant notBefore, Instant expiresAt, Instant at) {
        Instant from = signed(notBefore);
        Instant until = signed(expiresAt);
        return (from == null || !from.isAfter(at)) && (until == null || until.isAfter(at));
    }

    /**
     * The bound the canonical policy bytes carry: whole milliseconds, where the epoch's first millisecond is
     * written as 0, the same as a missing bound.
     */
    private static Instant signed(Instant bound) {
        if (bound == null) {
            return null;
        }
        Instant millis = bound.truncatedTo(ChronoUnit.MILLIS);
        return millis.equals(Instant.EPOCH) ? null : millis;
    }
}
