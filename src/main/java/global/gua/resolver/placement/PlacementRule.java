package global.gua.resolver.placement;

import java.util.Optional;

public interface PlacementRule {

    /** Empty defers to the next rule. */
    Optional<PlacementDecision> evaluate(PlacementContext context);

    /** Lower runs first. */
    int priority();

    default String name() {
        return getClass().getSimpleName();
    }
}
