package global.gua.resolver.policy;

import java.time.Instant;

/**
 * A signed window that opens at {@code notBefore} and closes at {@code expiresAt}. A missing bound is open, and so
 * is one at the epoch, because the canonical policy bytes write both as 0.
 */
final class ValidityWindow {

    private ValidityWindow() {}

    static boolean contains(Instant notBefore, Instant expiresAt, Instant at) {
        return (isOpen(notBefore) || !notBefore.isAfter(at)) && (isOpen(expiresAt) || expiresAt.isAfter(at));
    }

    private static boolean isOpen(Instant bound) {
        return bound == null || bound.equals(Instant.EPOCH);
    }
}
