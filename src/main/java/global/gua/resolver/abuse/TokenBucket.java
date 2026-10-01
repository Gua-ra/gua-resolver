package global.gua.resolver.abuse;

import java.time.Duration;

final class TokenBucket {

    private final long capacity;
    private final double tokensPerNano;
    private final long warnWindowNanos;
    private double tokens;
    private long lastRefillNanos;
    private boolean warned;
    private long warnedAtNanos;

    TokenBucket(long capacity, long tokensPerPeriod, Duration period, long nowNanos) {
        if (capacity < 1 || tokensPerPeriod < 1 || period == null || period.isZero() || period.isNegative()) {
            throw new IllegalArgumentException("capacity and tokensPerPeriod must be >= 1 and period > 0");
        }
        this.capacity = capacity;
        this.tokensPerNano = (double) tokensPerPeriod / period.toNanos();
        this.warnWindowNanos = period.toNanos();
        this.tokens = capacity;
        this.lastRefillNanos = nowNanos;
    }

    /** Returns 0 when granted, otherwise the nanoseconds until the next token. */
    synchronized long tryAcquire(long nowNanos) {
        refill(nowNanos);
        if (tokens >= 1.0) {
            tokens -= 1.0;
            return 0;
        }
        return Math.max(1L, (long) Math.ceil((1.0 - tokens) / tokensPerNano));
    }

    synchronized boolean firstLimitInWindow(long nowNanos) {
        if (!warned || nowNanos - warnedAtNanos >= warnWindowNanos) {
            warned = true;
            warnedAtNanos = nowNanos;
            return true;
        }
        return false;
    }

    private void refill(long nowNanos) {
        long elapsed = nowNanos - lastRefillNanos;
        if (elapsed <= 0) {
            return;
        }
        tokens = Math.min(capacity, tokens + elapsed * tokensPerNano);
        lastRefillNanos = nowNanos;
    }
}
