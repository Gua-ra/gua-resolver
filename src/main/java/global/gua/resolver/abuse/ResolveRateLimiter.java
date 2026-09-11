package global.gua.resolver.abuse;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;

import global.gua.resolver.config.ResolverProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Two-layer token-bucket limiter for {@code POST /resolve}: one bucket per client key, held in a bounded
 * cache (max size + idle expiry), and one global ceiling for the whole process. Both are per pod: with more
 * than one replica each pod enforces its own copy, so the effective per-client rate is replicas times the
 * configured limit. The per-source limit shared across replicas is the rate-limit middleware on the resolver
 * ingress, defined in gua-deploy; this is the floor that holds even for a request that reaches a pod directly.
 *
 * <p>Order: the client bucket is charged first, so an abuser is the one that runs dry and gets identified;
 * the global bucket is checked second. A request refused by the global bucket has already spent one client
 * token, which is accepted: under a flood the honest client's next request is throttled per client too
 * rather than retried into the flood.
 *
 * <p>Eviction is the bounded-memory trade-off: past {@code max-tracked-clients} active keys the least
 * recently used bucket is dropped and that client starts over with a full bucket. The global ceiling still
 * bounds the total rate whatever the key churn.
 */
public class ResolveRateLimiter {

    public enum Scope { CLIENT, GLOBAL }

    /** Outcome for one request. {@code firstHitInWindow} is set on the first refusal per key per window. */
    public record Decision(boolean allowed, Scope scope, long retryAfterSeconds, boolean firstHitInWindow) {
        static final Decision ALLOWED = new Decision(true, null, 0, false);
    }

    /** {@code gua_resolver_resolve_ratelimited_total{scope="client"|"global"}}. */
    public static final String LIMITED_METRIC = "gua.resolver.resolve.ratelimited";
    /** {@code gua_resolver_resolve_clients_tracked}: distinct client keys currently held. */
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

    /** Distinct client keys held right now, after the cache has applied pending evictions. */
    public long trackedClients() {
        clients.cleanUp();
        return clients.estimatedSize();
    }

    private static long ceilSeconds(long nanos) {
        return Math.max(1L, (nanos + 999_999_999L) / 1_000_000_000L);
    }
}
