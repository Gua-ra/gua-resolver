package global.gua.resolver.metrics;

import org.springframework.stereotype.Component;

import global.gua.resolver.roster.RosterStore;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Federation-state gauges, so the dashboard can show the live roster + transparency-log at a glance:
 * <ul>
 *   <li>{@code gua_resolver_roster_version} — current signed-roster version,</li>
 *   <li>{@code gua_resolver_roster_homeservers{status="active"}} — admitted, active homeservers,</li>
 *   <li>{@code gua_resolver_transparency_log_size} — append-only membership-event count.</li>
 * </ul>
 * Gauges read the current roster on scrape, so they always reflect live state.
 */
@Component
public class RosterMetrics {

    public RosterMetrics(RosterStore rosterStore, MeterRegistry metrics) {
        metrics.gauge("gua.resolver.roster.version", rosterStore,
                rs -> safe(() -> rs.current().version()));
        metrics.gauge("gua.resolver.transparency.log.size", rosterStore,
                rs -> safe(() -> rs.current().logCheckpoint().size()));
        io.micrometer.core.instrument.Gauge
                .builder("gua.resolver.roster.homeservers", rosterStore,
                        rs -> safe(() -> rs.current().activeEntries().size()))
                .tag("status", "active")
                .register(metrics);
    }

    private static double safe(java.util.function.Supplier<Number> f) {
        try {
            return f.get().doubleValue();
        } catch (Exception e) {
            return Double.NaN;   // surfaced as "no data" rather than a misleading 0
        }
    }
}
