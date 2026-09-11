package global.gua.resolver.abuse;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import global.gua.resolver.config.ResolverProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import static org.assertj.core.api.Assertions.assertThat;

class ResolveRateLimiterTest {

    private final FakeTicker ticker = new FakeTicker();
    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();

    private static ResolverProperties.Abuse props(int clientLimit, int globalLimit) {
        ResolverProperties.Abuse p = new ResolverProperties.Abuse();
        p.setClientLimitForPeriod(clientLimit);
        p.setClientBurst(clientLimit);
        p.setClientRefreshPeriod(Duration.ofMinutes(1));
        p.setGlobalLimitForPeriod(globalLimit);
        p.setGlobalBurst(globalLimit);
        p.setGlobalRefreshPeriod(Duration.ofSeconds(1));
        return p;
    }

    private double limited(String scope) {
        return metrics.get(ResolveRateLimiter.LIMITED_METRIC).tag("scope", scope).counter().count();
    }

    @Test
    void nAllowedThenNPlusOneIsRefusedPerClientWithARetryAfter() {
        ResolveRateLimiter limiter = new ResolveRateLimiter(props(20, 1_000), metrics, ticker);
        for (int i = 0; i < 20; i++) {
            assertThat(limiter.check("a").allowed()).as("request %d", i + 1).isTrue();
        }
        ResolveRateLimiter.Decision refused = limiter.check("a");
        assertThat(refused.allowed()).isFalse();
        assertThat(refused.scope()).isEqualTo(ResolveRateLimiter.Scope.CLIENT);
        assertThat(refused.retryAfterSeconds()).isEqualTo(3);          // 20 per minute = one every 3s
        assertThat(refused.firstHitInWindow()).isTrue();
        assertThat(limiter.check("a").firstHitInWindow()).isFalse();   // one WARN per key per window
        assertThat(limited("client")).isEqualTo(2);
        assertThat(limited("global")).isZero();

        // another client is unaffected
        assertThat(limiter.check("b").allowed()).isTrue();

        // the refill lets the limited client through again
        ticker.advance(Duration.ofSeconds(3));
        assertThat(limiter.check("a").allowed()).isTrue();
        assertThat(limiter.check("a").allowed()).isFalse();
    }

    @Test
    void globalCeilingRefusesAcrossClients() {
        ResolveRateLimiter limiter = new ResolveRateLimiter(props(100, 5), metrics, ticker);
        for (int i = 0; i < 5; i++) {
            assertThat(limiter.check("client-" + i).allowed()).isTrue();
        }
        ResolveRateLimiter.Decision refused = limiter.check("client-5");
        assertThat(refused.allowed()).isFalse();
        assertThat(refused.scope()).isEqualTo(ResolveRateLimiter.Scope.GLOBAL);
        assertThat(refused.retryAfterSeconds()).isEqualTo(1);
        assertThat(refused.firstHitInWindow()).isTrue();
        assertThat(limiter.check("client-6").firstHitInWindow()).isFalse();
        assertThat(limited("global")).isEqualTo(2);
        assertThat(limited("client")).isZero();

        ticker.advance(Duration.ofSeconds(1));
        assertThat(limiter.check("client-7").allowed()).isTrue();
    }

    @Test
    void trackedClientStateIsBoundedAndExpires() {
        ResolverProperties.Abuse p = props(20, 1_000);
        p.setMaxTrackedClients(100);
        p.setClientExpiry(Duration.ofMinutes(5));
        ResolveRateLimiter limiter = new ResolveRateLimiter(p, metrics, ticker);

        for (int i = 0; i < 500; i++) {
            limiter.check("client-" + i);
        }
        assertThat(limiter.trackedClients()).isBetween(1L, 100L);
        assertThat(metrics.get(ResolveRateLimiter.TRACKED_METRIC).gauge().value()).isBetween(1.0, 100.0);

        ticker.advance(Duration.ofMinutes(5).plusSeconds(1));
        assertThat(limiter.trackedClients()).isZero();
    }

    @Test
    void disabledLimiterAllowsEverything() {
        ResolverProperties.Abuse p = props(1, 1);
        p.setEnabled(false);
        ResolveRateLimiter limiter = new ResolveRateLimiter(p, metrics, ticker);
        for (int i = 0; i < 50; i++) {
            assertThat(limiter.check("a").allowed()).isTrue();
        }
        assertThat(limited("client")).isZero();
        assertThat(limited("global")).isZero();
    }

    @Test
    void defaultsAreTwentyPerMinutePerClientAndTwoHundredPerSecondGlobally() {
        ResolverProperties.Abuse p = new ResolverProperties.Abuse();
        assertThat(p.isEnabled()).isTrue();
        assertThat(p.getClientLimitForPeriod()).isEqualTo(20);
        assertThat(p.getClientBurst()).isEqualTo(20);
        assertThat(p.getClientRefreshPeriod()).isEqualTo(Duration.ofMinutes(1));
        assertThat(p.getGlobalLimitForPeriod()).isEqualTo(200);
        assertThat(p.getGlobalBurst()).isEqualTo(200);
        assertThat(p.getGlobalRefreshPeriod()).isEqualTo(Duration.ofSeconds(1));
        assertThat(p.isTraceEnabled()).isFalse();
    }
}
