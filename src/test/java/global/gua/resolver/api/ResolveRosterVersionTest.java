package global.gua.resolver.api;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import global.gua.resolver.claims.RoutingClaimsReplayStore;
import global.gua.resolver.claims.RoutingClaimsVerifier;
import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.service.ResolutionService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ResolveRosterVersionTest {

    private static final Homeserver HS = new Homeserver("hs", "hs.test", "https://matrix.hs.test",
            "https://account.hs.test", null, 1, true, "");

    private static SignedRoster roster(long version) {
        return new SignedRoster(version, Instant.parse("2026-10-29T00:00:00Z"), List.of(),
                new SignedRoster.LogCheckpoint("root", version), List.of());
    }

    private static ResolveController.ResolveResponse placeWhileTheRosterReads(SignedRoster first, SignedRoster then) {
        RosterStore store = mock(RosterStore.class);
        when(store.current()).thenReturn(first, then);
        ResolutionService resolution = mock(ResolutionService.class);
        when(resolution.resolvePhone(any())).thenReturn(Optional.empty());
        when(resolution.placementDecisionFor(any())).thenReturn(
                PlacementDecision.of(HS, "WeightedFallbackRule", "weighted-fallback", "stable weighted fallback"));
        ResolverProperties props = new ResolverProperties();
        ResolveController controller = new ResolveController(resolution, store,
                new RoutingClaimsVerifier(props, mock(RoutingClaimsReplayStore.class)), props,
                new SimpleMeterRegistry());
        return controller.resolve(new ResolveController.ResolveRequest("+5511987654321", null, null, null, null,
                null, null, null, null));
    }

    @Test
    void anAnswerNamesTheRosterItWasMadeAgainst() {
        assertThat(placeWhileTheRosterReads(roster(7), roster(7)).rosterVersion()).isEqualTo(7L);
    }

    @Test
    void anAnswerMadeWhileTheRosterChangedNamesNoVersion() {
        assertThat(placeWhileTheRosterReads(roster(7), roster(8)).rosterVersion()).isNull();
    }
}
