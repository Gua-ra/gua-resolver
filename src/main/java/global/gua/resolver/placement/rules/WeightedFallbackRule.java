package global.gua.resolver.placement.rules;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementRule;
import global.gua.resolver.roster.RosterStore;

/**
 * Last-resort placement: spread new accounts across all homeservers that accept new accounts, proportional
 * to their configured weight. Always registered LAST so {@link global.gua.resolver.placement.PlacementEngine}
 * never runs dry. With a single homeserver (the dev case) this trivially returns it.
 */
@Component
@Order(Integer.MAX_VALUE)
public class WeightedFallbackRule implements PlacementRule {

    private final RosterStore rosterStore;

    public WeightedFallbackRule(RosterStore rosterStore) {
        this.rosterStore = rosterStore;
    }

    @Override
    public Optional<Homeserver> evaluate(PlacementContext context) {
        List<Homeserver> candidates = rosterStore.current().activeEntries().stream()
                .map(e -> e.homeserver())
                .filter(Homeserver::acceptsNew)
                .toList();
        if (candidates.isEmpty()) {
            return Optional.empty();
        }
        int totalWeight = candidates.stream().mapToInt(hs -> Math.max(0, hs.weight())).sum();
        if (totalWeight <= 0) {
            return Optional.of(candidates.get(ThreadLocalRandom.current().nextInt(candidates.size())));
        }
        int target = ThreadLocalRandom.current().nextInt(totalWeight);
        int cumulative = 0;
        for (Homeserver hs : candidates) {
            cumulative += Math.max(0, hs.weight());
            if (target < cumulative) {
                return Optional.of(hs);
            }
        }
        return Optional.of(candidates.get(candidates.size() - 1));
    }

    @Override
    public int priority() {
        return Integer.MAX_VALUE;
    }
}
