package global.gua.resolver.metrics;

import org.springframework.stereotype.Component;

import global.gua.resolver.roster.RosterStore;
import io.micrometer.core.instrument.MeterRegistry;

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
        io.micrometer.core.instrument.Gauge
                .builder("gua.resolver.roster.homeservers", rosterStore,
                        rs -> safe(rs::unattestedActiveCount))
                .tag("status", "unattested")
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
