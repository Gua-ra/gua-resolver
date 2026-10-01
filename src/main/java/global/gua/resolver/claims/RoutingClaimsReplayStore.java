package global.gua.resolver.claims;

import java.time.Instant;

public interface RoutingClaimsReplayStore {

    boolean recordIfNew(String issuer, String nonce, Instant expiresAt);

    void removeExpired(Instant now);
}
