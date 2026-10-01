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

/** Served on the resolver origin: the apex {@code /.well-known/*} paths belong to another service. */
@RestController
public class WellKnownController {

    private final GenesisLoader genesis;

    public WellKnownController(GenesisLoader genesis) {
        this.genesis = genesis;
    }

    public record FederationDocument(String genesisId, String fingerprint, String chainHead,
                                     FederationGenesis genesis,
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
                        global.gua.resolver.governance.CanonicalGenesis.fingerprint(id),
                        genesis.chainHead(), loaded, genesis.transitions()));
    }
}
