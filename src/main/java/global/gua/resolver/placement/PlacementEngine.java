package global.gua.resolver.placement;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import global.gua.resolver.domain.Homeserver;

/**
 * Runs the registered {@link PlacementRule}s in priority order and returns the first match. Placement is a
 * pure function of (context, current roster) so it is deterministic: the same input always yields the same
 * homeserver. The decision is made once, at account creation (MXIDs are immutable).
 *
 * <p>Spring injects every {@link PlacementRule} bean; the claim rules read the signed roster, so adding a
 * carrier/institution is a roster edit, not a code change.
 */
@Component
public class PlacementEngine {

    private static final Logger log = LoggerFactory.getLogger(PlacementEngine.class);

    private final List<PlacementRule> rules;

    public PlacementEngine(List<PlacementRule> rules) {
        this.rules = rules.stream().sorted(Comparator.comparingInt(PlacementRule::priority)).toList();
        log.info("PlacementEngine initialised with rules (in order): {}",
                this.rules.stream().map(PlacementRule::name).toList());
    }

    /**
     * @return the homeserver a new account with this context should be created on.
     * @throws IllegalStateException if no rule (including the weighted fallback) yields a homeserver.
     */
    public Homeserver decide(PlacementContext context) {
        for (PlacementRule rule : rules) {
            Optional<Homeserver> choice = rule.evaluate(context);
            if (choice.isPresent()) {
                log.debug("Placement: {} -> {} (by {})", context.country(), choice.get().id(), rule.name());
                return choice.get();
            }
        }
        throw new IllegalStateException("No placement rule yielded a homeserver; "
                + "a WeightedFallbackRule over the enabled roster must always be registered last.");
    }
}
