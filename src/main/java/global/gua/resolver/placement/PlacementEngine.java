package global.gua.resolver.placement;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class PlacementEngine {

    private static final Logger log = LoggerFactory.getLogger(PlacementEngine.class);

    private final List<PlacementRule> rules;

    public PlacementEngine(List<PlacementRule> rules) {
        this.rules = rules.stream().sorted(Comparator.comparingInt(PlacementRule::priority)).toList();
        log.info("PlacementEngine initialised with rules (in order): {}",
                this.rules.stream().map(PlacementRule::name).toList());
    }

    public global.gua.resolver.domain.Homeserver decide(PlacementContext context) {
        return decideWithTrace(context).homeserver();
    }

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
