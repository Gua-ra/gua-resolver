/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

/**
 * The single condition every placement-custody bean is gated on.
 *
 * <p>Placement records are AUTHORITY-node state, and the whole feature is off unless a deployment turns it
 * on. With the shipped defaults none of these beans exists, no placement path is mapped, no scheduled job
 * runs and no table is read. The ingest path carries a second flag of its own
 * ({@code gua.resolver.placement.ingest-enabled}), so reads and writes roll out separately. No flag serves
 * routing from these records.
 */
public final class PlacementFeature {

    /** AUTHORITY mode and {@code gua.resolver.placement.enabled}. */
    public static final String ENABLED =
            "'${gua.resolver.mode:AUTHORITY}' == 'AUTHORITY' and ${gua.resolver.placement.enabled:false}";

    private PlacementFeature() {}
}
