package global.gua.resolver.placement;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.rules.ClaimRule;
import global.gua.resolver.placement.rules.WeightedFallbackRule;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the placement pipeline: a carrier claiming its MCCMNC wins, an affiliation claim wins,
 * and otherwise the weighted fallback always yields an enabled homeserver. Pure (no Spring).
 */
class PlacementEngineTest {

    private static final Homeserver CARRIER = new Homeserver(
            "carrier", "vivo.gua.global", "https://carrier", "https://carrier/auth", "BR", 1, true, null);
    private static final Homeserver UNI = new Homeserver(
            "uni", "usp.gua.global", "https://uni", "https://uni/auth", "BR", 1, true, null);
    private static final Homeserver DEFAULT = new Homeserver(
            "default", "gua.global", "https://default", "https://default/auth", null, 5, true, null);

    private static RosterStore rosterOf(RosterEntry... entries) {
        SignedRoster roster = new SignedRoster(1L, Instant.now(), List.of(entries),
                new SignedRoster.LogCheckpoint("test", entries.length), List.of());
        return new RosterStore() {
            @Override public SignedRoster current() { return roster; }
            @Override public SignedRoster refresh() { return roster; }
        };
    }

    private static RosterEntry entry(Homeserver hs, ClaimPredicate... claims) {
        return new RosterEntry(hs, List.of(claims), Instant.now(), RosterEntry.Status.ACTIVE);
    }

    private static PlacementEngine engineFor(RosterStore store) {
        // Registered out of priority order on purpose — the engine must sort them.
        return new PlacementEngine(List.of(new WeightedFallbackRule(store), new ClaimRule(store)));
    }

    @Test
    void carrierClaimByMccmncWins() {
        var carrierClaim = new ClaimPredicate(null, "72411", null, null, null, null, null, 100);
        var engine = engineFor(rosterOf(entry(CARRIER, carrierClaim), entry(DEFAULT)));

        var ctx = new PlacementContext("+5511987654321", "BR", "72411", "Vivo", null, List.of(), Map.of());

        assertThat(engine.decide(ctx).id()).isEqualTo("carrier");
    }

    @Test
    void affiliationClaimWins() {
        var uniClaim = new ClaimPredicate(null, null, null, null, "usp.br", null, null, 100);
        var engine = engineFor(rosterOf(entry(UNI, uniClaim), entry(DEFAULT)));

        var ctx = new PlacementContext("+5511000000000", "BR", null, null, null, List.of("usp.br"), Map.of());

        assertThat(engine.decide(ctx).id()).isEqualTo("uni");
    }

    @Test
    void noClaimMatchFallsBackToAnEnabledHomeserver() {
        var carrierClaim = new ClaimPredicate(null, "72411", null, null, null, null, null, 100);
        var engine = engineFor(rosterOf(entry(CARRIER, carrierClaim), entry(DEFAULT)));

        // A phone whose carrier nobody claims must still be placed (on an acceptsNew homeserver).
        var ctx = new PlacementContext("+15555550100", "US", "31000", "Verizon", null, List.of(), Map.of());

        var chosen = engine.decide(ctx);
        assertThat(chosen).isNotNull();
        assertThat(chosen.acceptsNew()).isTrue();
        assertThat(List.of("carrier", "default")).contains(chosen.id());
    }

    @Test
    void claimedButNotAcceptingNewIsNotPlacedThere() {
        var closed = new Homeserver("closed", "closed.gua.global", "https://c", "https://c/auth", "BR", 1, false, null);
        var carrierClaim = new ClaimPredicate(null, "72411", null, null, null, null, null, 100);
        var engine = engineFor(rosterOf(entry(closed, carrierClaim), entry(DEFAULT)));

        var ctx = new PlacementContext("+5511987654321", "BR", "72411", "Vivo", null, List.of(), Map.of());

        // The claiming homeserver isn't accepting new accounts, so placement falls through to the default.
        assertThat(engine.decide(ctx).id()).isEqualTo("default");
    }
}
