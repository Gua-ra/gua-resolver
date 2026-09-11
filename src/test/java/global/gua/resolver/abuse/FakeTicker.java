package global.gua.resolver.abuse;

import java.time.Duration;

import com.github.benmanes.caffeine.cache.Ticker;

/** A ticker the tests move by hand, shared by the bucket cache and the buckets themselves. */
final class FakeTicker implements Ticker {

    private long nanos = 1_000_000_000L;

    @Override
    public long read() {
        return nanos;
    }

    void advance(Duration d) {
        nanos += d.toNanos();
    }
}
