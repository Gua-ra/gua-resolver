/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

public class PlacementRecordException extends RuntimeException {

    private final transient PlacementRecordRejection rejection;

    public PlacementRecordException(PlacementRecordRejection rejection) {
        super(rejection.reason());
        this.rejection = rejection;
    }

    public PlacementRecordException(PlacementRecordRejection rejection, String detail) {
        super(rejection.reason() + ": " + detail);
        this.rejection = rejection;
    }

    public PlacementRecordRejection rejection() {
        return rejection;
    }

    public String reason() {
        return rejection.reason();
    }
}
