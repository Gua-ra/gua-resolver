package global.gua.resolver.placement.rules;

import java.util.Comparator;
import java.util.Optional;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.placement.PlacementRule;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;

@Component
@Order(100)
public class ClaimRule implements PlacementRule {

    private final RosterStore rosterStore;

    public ClaimRule(RosterStore rosterStore) {
        this.rosterStore = rosterStore;
    }

    @Override
    public Optional<PlacementDecision> evaluate(PlacementContext context) {
        return rosterStore.current().activeEntries().stream()
                .filter(entry -> entry.homeserver().acceptsNew())
                .flatMap(entry -> entry.claims().stream()
                        .filter(c -> !c.isRemote() && c.matchesLocally(context))
                        .map(c -> new Match(entry, c)))
                .min(Comparator.comparingInt((Match m) -> m.claim().priority())
                        .thenComparing(m -> m.entry().homeserver().id()))
                .map(m -> PlacementDecision.of(m.entry().homeserver(), name(),
                        "roster-claim:" + m.entry().homeserver().id() + ":" + m.claim().priority(),
                        "matched signed roster claim"));
    }

    @Override
    public int priority() {
        return 100;
    }

    private record Match(RosterEntry entry, ClaimPredicate claim) {}
}
