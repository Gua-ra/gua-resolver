package global.gua.resolver.placement;

import java.util.Optional;

import global.gua.resolver.domain.Homeserver;

/**
 * SPI for placement rules. The {@link PlacementEngine} runs enabled rules in priority order and takes the
 * first non-empty result, so a new placement strategy is a new {@code PlacementRule} bean — the engine is
 * never edited.
 *
 * <p>Most operator-specific placement is expressed as declarative {@link ClaimPredicate}s in the signed
 * roster (handled by the built-in claim rules); implement this interface only for genuinely new strategy
 * *mechanisms* (e.g. a different weighting algorithm), not per-operator data.
 */
public interface PlacementRule {

    /** @return the chosen homeserver, or empty to defer to the next rule. */
    Optional<Homeserver> evaluate(PlacementContext context);

    /** Lower runs first. */
    int priority();

    default String name() {
        return getClass().getSimpleName();
    }
}
