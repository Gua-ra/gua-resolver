package global.gua.resolver.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import global.gua.resolver.directory.DirectoryStore;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.placement.PlacementEngine;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;

/**
 * Resolution front-door logic: existing-account lookups hit the shared, persistent, peppered-HMAC
 * {@link DirectoryStore}; new accounts run the {@link PlacementEngine} over the verified roster. The
 * homeserver id from the directory is resolved to its full advertised endpoint via the roster, so a stale
 * directory row can never point a client at a suspended/revoked homeserver, and a stale phone row is never
 * mistaken for a phone with no account. See §3, §4 and §6.
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
    public Optional<Homeserver> resolvePhone(String e164Phone, SignedRoster roster) {
        return directory.homeserverIdForPhone(e164Phone).map(id -> activeHomeserverById(roster, id)
                .orElseThrow(() -> new HomeserverUnavailableException(id)));
    }

    @Override
    public Optional<Homeserver> resolveUsername(String username) {
        return directory.homeserverIdForUsername(username)
                .flatMap(id -> activeHomeserverById(rosterStore.current(), id));
    }

    @Override
    public Homeserver placementFor(PlacementContext context) {
        return placementDecisionFor(context).homeserver();
    }

    @Override
    public PlacementDecision placementDecisionFor(PlacementContext context) {
        return placementEngine.decideWithTrace(context);
    }

    /** Only resolve to homeservers that are currently ACTIVE in the verified roster. */
    private static Optional<Homeserver> activeHomeserverById(SignedRoster roster, String id) {
        return roster.activeEntries().stream()
                .map(RosterEntry::homeserver)
                .filter(hs -> hs.id().equals(id))
                .findFirst();
    }
}
