package global.gua.resolver.placement.rules;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;

class WeightedFallbackRuleTest {

    private static Homeserver homeserver(String id, int weight) {
        return new Homeserver(id, id + ".gua.test", "https://" + id, "https://" + id + "/auth", null, weight, true,
                null);
    }

    private static WeightedFallbackRule ruleOver(Homeserver... candidates) {
        List<RosterEntry> entries = Arrays.stream(candidates)
                .map(hs -> new RosterEntry(hs, List.of(), Instant.EPOCH, RosterEntry.Status.ACTIVE)).toList();
        SignedRoster roster = new SignedRoster(7L, Instant.EPOCH, entries,
                new SignedRoster.LogCheckpoint("test", 7), List.of());
        return new WeightedFallbackRule(new RosterStore() {
            @Override public SignedRoster current() { return roster; }
            @Override public SignedRoster refresh() { return roster; }
        });
    }

    private static PlacementContext phone(int i) {
        return PlacementContext.forPhone(String.format(Locale.ROOT, "+55219%08d", i));
    }

    @Test
    void decidesAtTheLimitAndMakesNoDecisionOnePastIt() {
        int half = 1 << 23;
        assertThat(ruleOver(homeserver("a", half), homeserver("b", half)).evaluate(phone(0))).isPresent();
        assertThat(ruleOver(homeserver("a", half), homeserver("b", half + 1)).evaluate(phone(0))).isEmpty();
    }

    @Test
    void makesNoDecisionWhenTheTotalPassesTheRangeOfTheHash() {
        WeightedFallbackRule rule = ruleOver(homeserver("a", Integer.MAX_VALUE), homeserver("b", Integer.MAX_VALUE),
                homeserver("c", Integer.MAX_VALUE));

        assertThat(rule.evaluate(phone(0))).isEmpty();
    }

    @Test
    void negativeWeightsCountAsZeroAgainstTheLimit() {
        WeightedFallbackRule rule = ruleOver(homeserver("a", 1 << 24), homeserver("b", -1), homeserver("c", 1));

        assertThat(rule.evaluate(phone(0))).isEmpty();
    }

    @Test
    void sharesFollowTheWeightsAtTheLimit() {
        WeightedFallbackRule rule = ruleOver(homeserver("a", 3 << 22), homeserver("b", 1 << 22));
        int samples = 20_000;
        long toA = IntStream.range(0, samples)
                .mapToObj(i -> rule.evaluate(phone(i)).map(PlacementDecision::homeserver).orElseThrow().id())
                .filter("a"::equals).count();

        assertThat((double) toA / samples).isBetween(0.735, 0.765);
    }
}
