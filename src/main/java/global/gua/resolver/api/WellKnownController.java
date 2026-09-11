package global.gua.resolver.api;

import java.util.List;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import global.gua.resolver.governance.FederationGenesis;
import global.gua.resolver.governance.GenesisLoader;
import global.gua.resolver.governance.GovernanceTransition;

import java.util.concurrent.TimeUnit;

/**
 * Publishes the pinned federation genesis and its governance key transitions (ADM-001 L10).
 *
 * <p>This endpoint is one of several channels, not the trust root. A genesis fetched here is signed by the
 * keys it enumerates, so it verifies against itself and proves nothing on its own; what makes it a root is an
 * operator or a client comparing its fingerprint against an independent channel, and first-party clients
 * pinning it at build time. Serving it here is what makes that comparison possible, and it is deliberately
 * cacheable and unauthenticated for the same reason.
 *
 * <p>It is served on the resolver origin rather than the apex, whose {@code /.well-known/*} paths belong to
 * a different service.
 */
@RestController
public class WellKnownController {

    private final GenesisLoader genesis;

    public WellKnownController(GenesisLoader genesis) {
        this.genesis = genesis;
    }

    /**
     * @param genesisId   SHA-256 of the genesis canonical bytes: the federation's identity
     * @param fingerprint the first 16 hex characters grouped in fours, for comparison by eye
     */
    public record FederationDocument(String genesisId, String fingerprint, FederationGenesis genesis,
                                     List<GovernanceTransition> transitions) {}

    @GetMapping("/.well-known/gua-federation")
    public ResponseEntity<FederationDocument> federation() {
        FederationGenesis loaded = genesis.genesis().orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND, "this resolver has no federation genesis configured"));
        String id = genesis.genesisId();
        return ResponseEntity.ok()
                .eTag("\"" + id + "\"")
                .cacheControl(CacheControl.maxAge(1, TimeUnit.DAYS).cachePublic())
                .body(new FederationDocument(id,
                        global.gua.resolver.governance.CanonicalGenesis.fingerprint(id), loaded,
                        genesis.transitions()));
    }
}
