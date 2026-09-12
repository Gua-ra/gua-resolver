/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

/**
 * The single condition every placement-custody bean is gated on (migration plan Phase 4, ADM-008).
 *
 * <p>Placement records are AUTHORITY-node state, and the whole feature is off unless a deployment turns it
 * on. With the shipped defaults none of these beans exists, no placement path is mapped, no scheduled job
 * runs and no table is read, so a resolver behaves exactly as it did before this phase. The ingest path
 * carries a second flag of its own ({@code gua.resolver.placement.ingest-enabled}), so reads and writes roll
 * out separately.
 *
 * <p>There is deliberately no flag that would serve routing from these records. Nothing in this phase reads
 * the table on the resolution path (ADM-008 decision 9).
 */
public final class PlacementFeature {

    /** AUTHORITY mode AND {@code gua.resolver.placement.enabled}; both keep their pre-placement defaults. */
    public static final String ENABLED =
            "'${gua.resolver.mode:AUTHORITY}' == 'AUTHORITY' and ${gua.resolver.placement.enabled:false}";

    private PlacementFeature() {}
}
