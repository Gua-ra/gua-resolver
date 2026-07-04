package global.gua.resolver.directory;

import java.util.Optional;

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

    private final WebClient upstream;
    private final PhoneHasher hasher;
    private final boolean failOpenOnLookupError;

    public RemoteDirectoryStore(ResolverProperties props, PhoneHasher hasher, WebClient.Builder builder) {
        this.hasher = hasher;
        this.failOpenOnLookupError = props.getDirectory().isFailOpenOnLookupError();
        this.upstream = builder.baseUrl(props.getMirror().getUpstreamUrl()).build();
    }

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
        try {
            LookupResponse r = upstream.get()
                    .uri(b -> b.path("/directory/lookup").queryParam(param, value).build())
                    .retrieve()
                    .bodyToMono(LookupResponse.class)
                    .block();
            return (r == null || r.homeserverId() == null) ? Optional.empty() : Optional.of(r.homeserverId());
        } catch (WebClientResponseException.NotFound e) {
            return Optional.empty();
        } catch (Exception e) {
            if (failOpenOnLookupError) {
                return Optional.empty();
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
