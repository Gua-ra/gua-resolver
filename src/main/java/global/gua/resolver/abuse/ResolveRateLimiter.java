package global.gua.resolver.abuse;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;

import global.gua.resolver.config.ResolverProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;

public class ResolveRateLimiter {

    public enum Scope { CLIENT, GLOBAL }

    public record Decision(boolean allowed, Scope scope, long retryAfterSeconds, boolean firstHitInWindow) {
        static final Decision ALLOWED = new Decision(true, null, 0, false);
    }

    public static final String LIMITED_METRIC = "gua.resolver.resolve.ratelimited";
    public static final String TRACKED_METRIC = "gua.resolver.resolve.clients.tracked";

    private final ResolverProperties.Abuse props;
    private final Ticker ticker;
    private final Cache<String, TokenBucket> clients;
    private final TokenBucket global;
    private final Counter limitedClient;
    private final Counter limitedGlobal;

    public ResolveRateLimiter(ResolverProperties.Abuse props, MeterRegistry metrics, Ticker ticker) {
        this.props = props;
        this.ticker = ticker;
        this.clients = Caffeine.newBuilder()
                .maximumSize(props.getMaxTrackedClients())
                .expireAfterAccess(props.getClientExpiry())
                .ticker(ticker)
                .build();
        this.global = new TokenBucket(props.getGlobalBurst(), props.getGlobalLimitForPeriod(),
                props.getGlobalRefreshPeriod(), ticker.read());
        this.limitedClient = Counter.builder(LIMITED_METRIC).tag("scope", "client")
                .description("/resolve requests refused by the per-client bucket").register(metrics);
        this.limitedGlobal = Counter.builder(LIMITED_METRIC).tag("scope", "global")
                .description("/resolve requests refused by the global ceiling").register(metrics);
        Gauge.builder(TRACKED_METRIC, clients, Cache::estimatedSize)
                .description("distinct /resolve client keys currently tracked (bounded by max-tracked-clients)")
                .register(metrics);
    }

    public Decision check(String clientKey) {
        if (!props.isEnabled()) {
            return Decision.ALLOWED;
        }
        long now = ticker.read();
        TokenBucket bucket = clients.get(clientKey, k -> new TokenBucket(props.getClientBurst(),
                props.getClientLimitForPeriod(), props.getClientRefreshPeriod(), now));
        long wait = bucket.tryAcquire(now);
        if (wait > 0) {
            limitedClient.increment();
            return new Decision(false, Scope.CLIENT, ceilSeconds(wait), bucket.firstLimitInWindow(now));
        }
        long globalWait = global.tryAcquire(now);
        if (globalWait > 0) {
            limitedGlobal.increment();
            return new Decision(false, Scope.GLOBAL, ceilSeconds(globalWait), global.firstLimitInWindow(now));
        }
        return Decision.ALLOWED;
    }

    public long trackedClients() {
        clients.cleanUp();
        return clients.estimatedSize();
    }

    private static long ceilSeconds(long nanos) {
        return Math.max(1L, (nanos + 999_999_999L) / 1_000_000_000L);
    }
}
