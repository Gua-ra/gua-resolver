package global.gua.resolver.claims;

import java.time.Instant;

/** Shared replay guard for short-lived signed routing claims. */
public interface RoutingClaimsReplayStore {

    /**
     * Records a claims nonce if it has not been seen before.
     *
     * @return true when the nonce was newly recorded; false when it was already used.
     */
    boolean recordIfNew(String issuer, String nonce, Instant expiresAt);

    void removeExpired(Instant now);
}
