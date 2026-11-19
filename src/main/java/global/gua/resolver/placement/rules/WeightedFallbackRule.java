package global.gua.resolver.placement.rules;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    /**
     * Up to this total, reducing the signed 32-bit hash modulo the total keeps every candidate's chance within
     * 1/256 of its share. Above it the fallback makes no decision, and admission and governance refuse weights
     * that would cross it. Raising it would change decisions for totals in between, so it is part of v1.
     */
    public static final long MAX_TOTAL_WEIGHT = 1L << 24;

    private static final Logger log = LoggerFactory.getLogger(WeightedFallbackRule.class);

    private final RosterStore rosterStore;
    private final AtomicLong reportedRosterVersion = new AtomicLong(-1);

    public WeightedFallbackRule(RosterStore rosterStore) {
        this.rosterStore = rosterStore;
    }

    /** Negative weights count as 0, as they do in the hash. */
    public static long totalWeight(Collection<Homeserver> homeservers) {
        return homeservers.stream().mapToLong(hs -> Math.max(0, hs.weight())).sum();
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
        long totalWeight = totalWeight(candidates);
        if (totalWeight > MAX_TOTAL_WEIGHT) {
            if (reportedRosterVersion.getAndSet(roster.version()) != roster.version()) {
                log.error("Weighted fallback makes no decision for roster {}: the homeservers accepting new "
                        + "accounts weigh {} in total, above the limit of {}", roster.version(), totalWeight,
                        MAX_TOTAL_WEIGHT);
            }
            return Optional.empty();
        }
        if (totalWeight == 0) {
            int index = Math.floorMod(stableHash(context, roster.version(), candidates), candidates.size());
            return Optional.of(PlacementDecision.of(candidates.get(index), name(), "weighted-fallback",
                    "stable fallback over equal-weight homeservers"));
        }
        long target = Math.floorMod((long) stableHash(context, roster.version(), candidates), totalWeight);
        long cumulative = 0;
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

    public static int stableHash(PlacementContext context, long rosterVersion, List<Homeserver> candidates) {
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
}
