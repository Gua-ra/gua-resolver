package global.gua.resolver.api;

import java.nio.charset.StandardCharsets;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.directory.DirectoryStore;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;

/**
 * The shared directory's write + lookup surface (§4). Writes are authenticated by the hosting homeserver's
 * <b>membership credential</b> (the Ed25519 signing key in its roster entry): a homeserver can only write
 * rows for accounts it hosts, because the write must be signed by the key the authority admitted for that
 * {@code homeserverId}. identity-service calls this at account provisioning. The lookup is rate-limited and
 * keyed by peppered HMAC (mirrors query it; no bulk export exists).
 */
@RestController
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class DirectoryController {

    private final DirectoryStore directory;
    private final RosterStore rosterStore;

    public DirectoryController(DirectoryStore directory, RosterStore rosterStore) {
        this.directory = directory;
        this.rosterStore = rosterStore;
    }

    /** A homeserver registers one of its accounts' phone/username → itself, signed with its signing key. */
    @PostMapping("/directory/entries")
    public ResponseEntity<Void> write(@Valid @RequestBody DirectoryWriteRequest req) {
        RosterEntry entry = rosterStore.current().activeEntries().stream()
                .filter(e -> e.homeserver().id().equals(req.homeserverId()))
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.FORBIDDEN,
                        "unknown or inactive homeserver: " + req.homeserverId()));

        String canonical = "directory-write.v1|" + req.homeserverId() + "|"
                + nz(req.e164Phone()) + "|" + nz(req.username());
        boolean ok = Ed25519.verify(Ed25519.publicKey(entry.homeserver().signingKey()),
                canonical.getBytes(StandardCharsets.UTF_8), req.signature());
        if (!ok) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid membership-credential signature");
        }

        if (req.e164Phone() != null && !req.e164Phone().isBlank()) {
            directory.putPhone(req.e164Phone(), req.homeserverId());
        }
        if (req.username() != null && !req.username().isBlank()) {
            directory.putUsername(req.username(), req.homeserverId());
        }
        return ResponseEntity.noContent().build();
    }

    /** Rate-limited lookup by peppered phone hash or username — what a mirror queries (never a bulk copy). */
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

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    public record DirectoryWriteRequest(
            @NotBlank String homeserverId,
            String e164Phone,
            String username,
            @NotBlank String signature) {}

    public record LookupResponse(String homeserverId) {}
}
