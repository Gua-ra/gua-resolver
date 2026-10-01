/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

public final class PlacementFeature {

    public static final String ENABLED =
            "'${gua.resolver.mode:AUTHORITY}' == 'AUTHORITY' and ${gua.resolver.placement.enabled:false}";

    private PlacementFeature() {}
}
