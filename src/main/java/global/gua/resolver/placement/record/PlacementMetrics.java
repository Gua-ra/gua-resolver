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

/**
 * {@code gua_resolver_placement_records{origin,homeserver}}: how many records this node holds, split by the
 * homeserver that holds the accounts and by whether the account is genesis-rooted or bootstrap.
 *
 * <p>Refreshed on a timer rather than on scrape because it is a grouped query, and the cardinality is bounded
 * by the roster size times two. The counters live where the decisions are made: accepted records and
 * rejections in the ingest service, conflicts in the same place, orphaned records in the auditor.
 */
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
