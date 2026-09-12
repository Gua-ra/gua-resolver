/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

/**
 * A placement record that was refused, carrying the one reason it was refused for. Thrown by the codec, the
 * verifier and the storage rules alike, so every refusal reaches the caller and the metrics through one
 * path. A refused record is never partially accepted and never repaired.
 */
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

    /** The stable code: the API error code and the metric tag value. */
    public String reason() {
        return rejection.reason();
    }
}
