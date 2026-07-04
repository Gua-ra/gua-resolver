package global.gua.resolver.claims;

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@DirtiesContext
class JdbcRoutingClaimsReplayStoreTest {

    @Autowired JdbcRoutingClaimsReplayStore store;

    @Test
    void recordsNonceOnlyOnceAndCleansExpiredRows() {
        Instant now = Instant.now();

        assertThat(store.recordIfNew("https://account.gua.test", "nonce-1", now.plusSeconds(60))).isTrue();
        assertThat(store.recordIfNew("https://account.gua.test", "nonce-1", now.plusSeconds(60))).isFalse();

        store.removeExpired(now.plusSeconds(120));

        assertThat(store.recordIfNew("https://account.gua.test", "nonce-1", now.plusSeconds(180))).isTrue();
    }
}
