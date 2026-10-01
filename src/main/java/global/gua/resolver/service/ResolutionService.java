package global.gua.resolver.service;

import java.util.Optional;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;

public interface ResolutionService {

    Optional<Homeserver> resolvePhone(String e164Phone);

    Optional<Homeserver> resolveUsername(String username);

    Homeserver placementFor(PlacementContext context);

    PlacementDecision placementDecisionFor(PlacementContext context);
}
