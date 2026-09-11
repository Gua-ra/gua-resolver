package global.gua.resolver.abuse;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenBucketTest {

    private static final long T0 = 5_000_000_000L;

    @Test
    void burstIsGrantedThenTheNextRequestWaitsForARefill() {
        // 3 per minute, burst 3: one token every 20 seconds once the burst is spent.
        TokenBucket bucket = new TokenBucket(3, 3, Duration.ofMinutes(1), T0);
        assertThat(bucket.tryAcquire(T0)).isZero();
        assertThat(bucket.tryAcquire(T0)).isZero();
        assertThat(bucket.tryAcquire(T0)).isZero();
        long wait = bucket.tryAcquire(T0);
        assertThat(wait).isEqualTo(Duration.ofSeconds(20).toNanos());

        // 19s later still nothing; at 20s exactly one token has been earned.
        assertThat(bucket.tryAcquire(T0 + Duration.ofSeconds(19).toNanos())).isPositive();
        assertThat(bucket.tryAcquire(T0 + Duration.ofSeconds(20).toNanos())).isZero();
        assertThat(bucket.tryAcquire(T0 + Duration.ofSeconds(20).toNanos())).isPositive();
    }

    @Test
    void refillNeverExceedsCapacity() {
        TokenBucket bucket = new TokenBucket(2, 2, Duration.ofSeconds(1), T0);
        long muchLater = T0 + Duration.ofHours(1).toNanos();
        assertThat(bucket.tryAcquire(muchLater)).isZero();
        assertThat(bucket.tryAcquire(muchLater)).isZero();
        assertThat(bucket.tryAcquire(muchLater)).isPositive();
    }

    @Test
    void firstLimitInWindowFiresOncePerRefreshPeriod() {
        TokenBucket bucket = new TokenBucket(1, 1, Duration.ofMinutes(1), T0);
        assertThat(bucket.firstLimitInWindow(T0)).isTrue();
        assertThat(bucket.firstLimitInWindow(T0 + Duration.ofSeconds(30).toNanos())).isFalse();
        assertThat(bucket.firstLimitInWindow(T0 + Duration.ofSeconds(59).toNanos())).isFalse();
        assertThat(bucket.firstLimitInWindow(T0 + Duration.ofSeconds(60).toNanos())).isTrue();
        assertThat(bucket.firstLimitInWindow(T0 + Duration.ofSeconds(61).toNanos())).isFalse();
    }

    @Test
    void rejectsDegenerateConfiguration() {
        assertThatThrownBy(() -> new TokenBucket(0, 1, Duration.ofSeconds(1), T0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TokenBucket(1, 0, Duration.ofSeconds(1), T0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TokenBucket(1, 1, Duration.ZERO, T0))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
