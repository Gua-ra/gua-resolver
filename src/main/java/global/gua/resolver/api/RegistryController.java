package global.gua.resolver.api;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import global.gua.resolver.governance.Registry;
import global.gua.resolver.governance.RegistryService;

/**
 * Public distribution of the governance-signed HomeserverRegistry epochs (ADM-001 L10). A client, mirror or
 * auditor fetches an epoch and verifies it back to the pinned genesis without trusting this resolver: the
 * epoch carries its own governance signatures, names the genesis it descends from, and chains to the epoch
 * before it.
 *
 * <p>Both the epoch and the content it commits to are served, because an epoch alone carries only a content
 * hash, and a hash that a reader cannot expand into the membership it stands for is not verifiable.
 */
@RestController
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class RegistryController {

    private final RegistryService registry;

    public RegistryController(RegistryService registry) {
        this.registry = registry;
    }

    @GetMapping("/registry/homeservers/epoch/current")
    public RegistryService.PublishedEpoch current() {
        return registry.current(Registry.HOMESERVERS).orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND, "no membership epoch has been accepted yet"));
    }

    @GetMapping("/registry/homeservers/epoch/{epoch}")
    public RegistryService.PublishedEpoch at(@PathVariable long epoch) {
        return registry.at(Registry.HOMESERVERS, epoch).orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND, "no such membership epoch: " + epoch));
    }
}
