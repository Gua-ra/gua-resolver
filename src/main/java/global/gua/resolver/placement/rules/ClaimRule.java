package global.gua.resolver.placement.rules;

import java.util.Comparator;
import java.util.Optional;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementRule;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;

/**
 * Honours operator-declared {@link ClaimPredicate}s from the signed roster: a carrier claiming its MCCMNC,
 * a university claiming an affiliation domain, a region claiming a phone prefix, etc. This is how the
 * Brazil carrier-agreement scenario works — a carrier's homeserver entry declares {@code {mccmnc:"72411"}}
 * and matching signups land there automatically, with no resolver code change.
 *
 * <p>Runs first (highest priority). Remote (webhook) claims are evaluated by a separate RemoteClaimRule so
 * this rule stays a pure, fast, local function. Among multiple local matches the lowest claim priority
 * wins; the authority guarantees non-overlap at admission, so ties are an edge case broken deterministically.
 */
@Component
@Order(100)
public class ClaimRule implements PlacementRule {

    private final RosterStore rosterStore;

    public ClaimRule(RosterStore rosterStore) {
        this.rosterStore = rosterStore;
    }

    @Override
    public Optional<Homeserver> evaluate(PlacementContext context) {
        return rosterStore.current().activeEntries().stream()
                .filter(entry -> entry.homeserver().acceptsNew())
                .flatMap(entry -> entry.claims().stream()
                        .filter(c -> !c.isRemote() && c.matchesLocally(context))
                        .map(c -> new Match(entry, c)))
                .min(Comparator.comparingInt((Match m) -> m.claim().priority())
                        .thenComparing(m -> m.entry().homeserver().id()))
                .map(m -> m.entry().homeserver());
    }

    @Override
    public int priority() {
        return 100;
    }

    private record Match(RosterEntry entry, ClaimPredicate claim) {}
}
