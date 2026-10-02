package global.gua.resolver.service;

import java.util.Optional;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;

/**
 * The read front-door logic: given a phone (or username), where does or should the account live? Nothing
 * about the identifier is verified by the resolver.
 *
 * <p>Privacy: the phone is looked up by peppered HMAC against the shared directory; raw numbers are never
 * stored or logged, lookups are rate-limited, and the directory is never bulk-exported to mirrors.
 */
public interface ResolutionService {

    /** Where an existing account for this phone lives, if any. Empty means no account yet, so register. */
    Optional<Homeserver> resolvePhone(String e164Phone);

    /** Where an existing global username lives, if any (the federation locate-by-handle lookup). */
    Optional<Homeserver> resolveUsername(String username);

    /** Where a new account for this context should be registered (runs the placement engine). */
    Homeserver placementFor(PlacementContext context);

    /** Same placement answer with rule/policy trace metadata for audit/debug flows. */
    PlacementDecision placementDecisionFor(PlacementContext context);
}
