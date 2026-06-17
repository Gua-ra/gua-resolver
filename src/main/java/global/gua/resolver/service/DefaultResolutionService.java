package global.gua.resolver.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import global.gua.resolver.directory.DirectoryStore;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementEngine;
import global.gua.resolver.roster.RosterStore;

/**
 * Resolution front-door logic: existing-account lookups hit the shared, persistent, peppered-HMAC
 * {@link DirectoryStore}; new accounts run the {@link PlacementEngine} over the verified roster. The
 * homeserver id from the directory is resolved to its full advertised endpoint via the current roster, so
 * a stale directory row can never point a client at a suspended/revoked homeserver. See §3–§4 + §6.
 */
@Service
public class DefaultResolutionService implements ResolutionService {

    private final PlacementEngine placementEngine;
    private final RosterStore rosterStore;
    private final DirectoryStore directory;

    public DefaultResolutionService(PlacementEngine placementEngine, RosterStore rosterStore,
                                    DirectoryStore directory) {
        this.placementEngine = placementEngine;
        this.rosterStore = rosterStore;
        this.directory = directory;
    }

    @Override
    public Optional<Homeserver> resolvePhone(String e164Phone) {
        return directory.homeserverIdForPhone(e164Phone).flatMap(this::activeHomeserverById);
    }

    @Override
    public Optional<Homeserver> resolveUsername(String username) {
        return directory.homeserverIdForUsername(username).flatMap(this::activeHomeserverById);
    }

    @Override
    public Homeserver placementFor(PlacementContext context) {
        return placementEngine.decide(context);
    }

    /** Only resolve to homeservers that are currently ACTIVE in the verified roster. */
    private Optional<Homeserver> activeHomeserverById(String id) {
        return rosterStore.current().activeEntries().stream()
                .map(global.gua.resolver.roster.RosterEntry::homeserver)
                .filter(hs -> hs.id().equals(id))
                .findFirst();
    }
}
