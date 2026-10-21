package global.gua.resolver.api;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import global.gua.resolver.directory.DirectoryStore;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;

/**
 * The shared directory's lookup surface. The directory has no HTTP write path; the rows it holds are read
 * here and by {@code /resolve}. The lookup is rate limited and keyed by peppered HMAC (mirrors query it; no
 * bulk export exists).
 */
@RestController
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class DirectoryController {

    private final DirectoryStore directory;

    public DirectoryController(DirectoryStore directory) {
        this.directory = directory;
    }

    /** Rate-limited lookup by peppered phone hash or username: what a mirror queries (never a bulk copy). */
    @GetMapping("/directory/lookup")
    @RateLimiter(name = "directoryLookup")
    public LookupResponse lookup(@RequestParam(required = false) String phoneHash,
                                 @RequestParam(required = false) String username) {
        // The caller (mirror / identity-service) holds the shared pepper and sends the already-computed
        // hash, so the raw phone never crosses the wire.
        String hsId = (phoneHash != null && !phoneHash.isBlank())
                ? directory.homeserverIdForPhoneHash(phoneHash).orElse(null)
                : (username != null ? directory.homeserverIdForUsername(username).orElse(null) : null);
        if (hsId == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return new LookupResponse(hsId);
    }

    public record LookupResponse(String homeserverId) {}
}
