package global.gua.resolver.placement.rules;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.placement.PlacementRule;
import global.gua.resolver.roster.RosterStore;

/**
 * Last-resort placement: spread new accounts across homeservers that accept new accounts, proportional to
 * weight, but using stable hashing instead of randomness. The same context + roster snapshot yields the
 * same homeserver, which makes resolver answers reproducible across nodes and mirrors.
 */
@Component
@Order(Integer.MAX_VALUE)
public class WeightedFallbackRule implements PlacementRule {

    private final RosterStore rosterStore;

    public WeightedFallbackRule(RosterStore rosterStore) {
        this.rosterStore = rosterStore;
    }

    @Override
    public Optional<PlacementDecision> evaluate(PlacementContext context) {
        var roster = rosterStore.current();
        List<Homeserver> candidates = roster.activeEntries().stream()
                .map(e -> e.homeserver())
                .filter(Homeserver::acceptsNew)
                .sorted(Comparator.comparing(Homeserver::id))
                .toList();
        if (candidates.isEmpty()) {
            return Optional.empty();
        }
        int totalWeight = candidates.stream().mapToInt(hs -> Math.max(0, hs.weight())).sum();
        if (totalWeight <= 0) {
            int index = positiveModulo(stableHash(context, roster.version(), candidates), candidates.size());
            return Optional.of(PlacementDecision.of(candidates.get(index), name(), "weighted-fallback",
                    "stable fallback over equal-weight homeservers"));
        }
        int target = positiveModulo(stableHash(context, roster.version(), candidates), totalWeight);
        int cumulative = 0;
        for (Homeserver hs : candidates) {
            cumulative += Math.max(0, hs.weight());
            if (target < cumulative) {
                return Optional.of(PlacementDecision.of(hs, name(), "weighted-fallback",
                        "stable weighted fallback"));
            }
        }
        return Optional.of(PlacementDecision.of(candidates.get(candidates.size() - 1), name(),
                "weighted-fallback", "stable weighted fallback"));
    }

    @Override
    public int priority() {
        return Integer.MAX_VALUE;
    }

    private static int stableHash(PlacementContext context, long rosterVersion, List<Homeserver> candidates) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(("weighted-fallback.v1\nroster=" + rosterVersion + "\n")
                    .getBytes(StandardCharsets.UTF_8));
            digest.update(context.canonicalRoutingKey().getBytes(StandardCharsets.UTF_8));
            for (Homeserver hs : candidates) {
                digest.update(("\n" + hs.id() + ":" + Math.max(0, hs.weight()))
                        .getBytes(StandardCharsets.UTF_8));
            }
            byte[] bytes = digest.digest();
            return ((bytes[0] & 0xff) << 24)
                    | ((bytes[1] & 0xff) << 16)
                    | ((bytes[2] & 0xff) << 8)
                    | (bytes[3] & 0xff);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static int positiveModulo(int value, int modulo) {
        return Math.floorMod(value, modulo);
    }
}
