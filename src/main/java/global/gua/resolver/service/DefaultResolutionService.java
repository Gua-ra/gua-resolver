package global.gua.resolver.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import global.gua.resolver.directory.DirectoryStore;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.placement.PlacementEngine;
import global.gua.resolver.roster.RosterStore;

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
        return placementDecisionFor(context).homeserver();
    }

    @Override
    public PlacementDecision placementDecisionFor(PlacementContext context) {
        return placementEngine.decideWithTrace(context);
    }

    private Optional<Homeserver> activeHomeserverById(String id) {
        return rosterStore.current().activeEntries().stream()
                .map(global.gua.resolver.roster.RosterEntry::homeserver)
                .filter(hs -> hs.id().equals(id))
                .findFirst();
    }
}
