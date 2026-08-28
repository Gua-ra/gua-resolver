package global.gua.resolver.claims;

import java.sql.Timestamp;
import java.time.Instant;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Database-backed replay guard shared by all resolver replicas using the same authority DB. */
@Component
public class JdbcRoutingClaimsReplayStore implements RoutingClaimsReplayStore {

    private final JdbcTemplate jdbc;

    public JdbcRoutingClaimsReplayStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public boolean recordIfNew(String issuer, String nonce, Instant expiresAt) {
        try {
            jdbc.update("""
                    INSERT INTO routing_claim_nonce (issuer, nonce, expires_at, first_seen_at)
                    VALUES (?, ?, ?, ?)
                    """, issuer, nonce, Timestamp.from(expiresAt), Timestamp.from(Instant.now()));
            return true;
        } catch (DuplicateKeyException e) {
            return false;
        }
    }

    @Override
    public void removeExpired(Instant now) {
        jdbc.update("DELETE FROM routing_claim_nonce WHERE expires_at < ?", Timestamp.from(now));
    }

    @Scheduled(fixedDelayString = "${gua.resolver.claims.replay-cleanup-interval:PT10M}")
    void removeExpiredScheduled() {
        removeExpired(Instant.now());
    }
}
