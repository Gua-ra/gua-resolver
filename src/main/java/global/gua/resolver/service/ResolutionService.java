package global.gua.resolver.service;

import java.util.Optional;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;

/**
 * The read front-door logic: given a verified phone (or username), where does / should the account live?
 *
 * <p>Privacy: the phone is looked up by peppered HMAC against the shared directory; raw numbers are never
 * stored or logged, lookups are rate-limited, and the directory is never bulk-exported to mirrors (see
 * docs/FEDERATION_ROUTING_DESIGN.md §4).
 */
public interface ResolutionService {

    /** Where an EXISTING account for this phone lives, if any. Empty = no account yet (→ register). */
    Optional<Homeserver> resolvePhone(String e164Phone);

    /** Where an EXISTING global username lives, if any (the federation locate-by-handle lookup). */
    Optional<Homeserver> resolveUsername(String username);

    /** Where a NEW account for this context should be registered (runs the placement engine). */
    Homeserver placementFor(PlacementContext context);
}
