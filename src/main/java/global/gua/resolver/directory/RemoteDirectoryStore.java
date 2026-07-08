package global.gua.resolver.directory;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import global.gua.resolver.config.ResolverProperties;

/**
 * Mirror-mode {@link DirectoryStore} (§4): the phone graph is sensitive (PII + enumeration risk), so a
 * mirror never holds a copy — it <b>queries</b> the upstream authority's rate-limited lookup endpoint by
 * peppered HMAC (computed locally; the raw phone never leaves this node). Writes are rejected: only the
 * hosting homeserver writes directory rows, at the authority.
 */
@Component
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "MIRROR")
public class RemoteDirectoryStore implements DirectoryStore {

    private static final Logger log = LoggerFactory.getLogger(RemoteDirectoryStore.class);

    private final WebClient upstream;
    private final PhoneHasher hasher;
    private final boolean failOpenOnLookupError;
    private final Duration lookupTimeout;
    private final Duration cacheTtl;
    // Last verified POSITIVE result per lookup key, for serve-stale-within-budget on an authority outage.
    private final Map<String, Cached> positiveCache = new ConcurrentHashMap<>();

    public RemoteDirectoryStore(ResolverProperties props, PhoneHasher hasher, WebClient.Builder builder) {
        this.hasher = hasher;
        this.failOpenOnLookupError = props.getDirectory().isFailOpenOnLookupError();
        this.lookupTimeout = props.getMirror().getLookupTimeout();
        this.cacheTtl = props.getMirror().getDirectoryCacheTtl();
        this.upstream = builder.baseUrl(props.getMirror().getUpstreamUrl()).build();
    }

    private record Cached(String homeserverId, Instant at) {}

    @Override
    public Optional<String> homeserverIdForPhone(String e164Phone) {
        return homeserverIdForPhoneHash(hasher.hashPhone(e164Phone));
    }

    @Override
    public Optional<String> homeserverIdForPhoneHash(String phoneHash) {
        return lookup("phoneHash", phoneHash);
    }

    @Override
    public Optional<String> homeserverIdForUsername(String username) {
        return lookup("username", username.trim().toLowerCase(java.util.Locale.ROOT));
    }

    private Optional<String> lookup(String param, String value) {
        String key = param + "=" + value;
        try {
            LookupResponse r = upstream.get()
                    .uri(b -> b.path("/directory/lookup").queryParam(param, value).build())
                    .retrieve()
                    .bodyToMono(LookupResponse.class)
                    .timeout(lookupTimeout)
                    .block(lookupTimeout.plusSeconds(1));
            if (r == null || r.homeserverId() == null) {
                return Optional.empty();
            }
            positiveCache.put(key, new Cached(r.homeserverId(), Instant.now()));
            return Optional.of(r.homeserverId());
        } catch (WebClientResponseException.NotFound e) {
            return Optional.empty();
        } catch (Exception e) {
            if (failOpenOnLookupError) {
                return Optional.empty();
            }
            // Authority unreachable: keep returning users resolvable by serving a recently-verified POSITIVE
            // mapping within the staleness budget. Negatives are never served stale (that would let an
            // existing account be treated as new). The result is still checked against the active roster
            // upstream in DefaultResolutionService, so a suspended/revoked homeserver is never returned.
            Cached cached = positiveCache.get(key);
            if (cached != null && !cacheTtl.isZero()
                    && Instant.now().isBefore(cached.at().plus(cacheTtl))) {
                log.warn("Authority directory unreachable; serving stale verified mapping for {} (age within {})",
                        param, cacheTtl);
                return Optional.of(cached.homeserverId());
            }
            throw new DirectoryUnavailableException("authority directory lookup unavailable", e);
        }
    }

    @Override
    public void putPhone(String e164Phone, String homeserverId) {
        throw new UnsupportedOperationException("a mirror does not write the directory");
    }

    @Override
    public void putUsername(String username, String homeserverId) {
        throw new UnsupportedOperationException("a mirror does not write the directory");
    }

    @Override
    public void removePhone(String e164Phone) {
        throw new UnsupportedOperationException("a mirror does not write the directory");
    }

    public record LookupResponse(String homeserverId) {}
}
