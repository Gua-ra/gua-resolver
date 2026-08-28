package global.gua.resolver.placement;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

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
     * @throws NoPlacementAvailableException if no rule (including the weighted fallback) yields a homeserver.
     */
    public global.gua.resolver.domain.Homeserver decide(PlacementContext context) {
        return decideWithTrace(context).homeserver();
    }

    /** Same placement decision, with the rule/policy metadata needed for debugging and audit. */
    public PlacementDecision decideWithTrace(PlacementContext context) {
        for (PlacementRule rule : rules) {
            Optional<PlacementDecision> choice = rule.evaluate(context);
            if (choice.isPresent()) {
                PlacementDecision decision = choice.get();
                log.debug("Placement: {} -> {} (by {}; reason={})",
                        context.country(), decision.homeserver().id(), rule.name(), decision.reason());
                return decision;
            }
        }
        throw new NoPlacementAvailableException("no homeserver is currently accepting new accounts");
    }
}
