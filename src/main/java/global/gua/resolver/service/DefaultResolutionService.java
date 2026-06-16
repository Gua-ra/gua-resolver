package global.gua.resolver.service;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementEngine;
import global.gua.resolver.roster.RosterStore;

/**
 * Phase-1 resolution: placement runs through the real {@link PlacementEngine}; existing-account lookup uses
 * an in-memory directory (empty at first, so new phones route to placement). The in-memory directory is a
 * stand-in for the shared, privacy-preserving (peppered-HMAC) phone→homeserver directory that identity-service
 * writes to — wired in the next pass. See docs/FEDERATION_ROUTING_DESIGN.md §4.
 */
@Service
public class DefaultResolutionService implements ResolutionService {

    private final PlacementEngine placementEngine;
    private final RosterStore rosterStore;

    /** Stub directory: phoneHash → homeserverId. Replaced by the shared directory store. */
    private final ConcurrentHashMap<String, String> directory = new ConcurrentHashMap<>();

    public DefaultResolutionService(PlacementEngine placementEngine, RosterStore rosterStore) {
        this.placementEngine = placementEngine;
        this.rosterStore = rosterStore;
    }

    @Override
    public Optional<Homeserver> resolvePhone(String e164Phone) {
        String hsId = directory.get(hash(e164Phone));
        return hsId == null ? Optional.empty() : homeserverById(hsId);
    }

    @Override
    public Optional<Homeserver> resolveUsername(String username) {
        return Optional.empty(); // backed by the directory's username index in the next pass
    }

    @Override
    public Homeserver placementFor(PlacementContext context) {
        return placementEngine.decide(context);
    }

    private Optional<Homeserver> homeserverById(String id) {
        return rosterStore.current().activeEntries().stream()
                .map(e -> e.homeserver())
                .filter(hs -> hs.id().equals(id))
                .findFirst();
    }

    /** Placeholder for the peppered HMAC; the real digest is computed with the shared pepper. */
    private String hash(String e164Phone) {
        return Integer.toHexString(e164Phone.hashCode());
    }
}
