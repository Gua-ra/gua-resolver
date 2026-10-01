/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.MultiGauge;
import io.micrometer.core.instrument.Tags;

@Component
@ConditionalOnExpression(PlacementFeature.ENABLED)
public class PlacementMetrics {

    private final JdbcPlacementRecordStore store;
    private final MultiGauge records;

    public PlacementMetrics(JdbcPlacementRecordStore store, MeterRegistry metrics) {
        this.store = store;
        this.records = MultiGauge.builder("gua.resolver.placement.records").register(metrics);
    }

    @Scheduled(fixedDelayString = "${gua.resolver.placement.metrics-interval:PT1M}")
    public void refresh() {
        records.register(store.counts().stream()
                .map(count -> MultiGauge.Row.of(
                        Tags.of("homeserver", count.homeserverId(), "origin", count.origin()),
                        count.count()))
                .toList(), true);
    }
}
