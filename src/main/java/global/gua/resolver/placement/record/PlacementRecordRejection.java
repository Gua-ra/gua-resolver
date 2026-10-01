/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

/** Declaration order is check order. Reasons above BAD_SIGNATURE never consult stored state. */
public enum PlacementRecordRejection {

    MALFORMED_ENVELOPE("malformed_envelope"),
    BAD_BASE64("bad_base64"),
    WRONG_LENGTH("wrong_length"),
    DECLARED_LENGTH_MISMATCH("declared_length_mismatch"),
    BAD_MAGIC("bad_magic"),
    UNSUPPORTED_VERSION("unsupported_version"),
    UNSUPPORTED_GENERATION("unsupported_generation"),
    BAD_ACCOUNT_ID_VERSION("bad_account_id_version"),
    UNKNOWN_ACCOUNT_CLASS("unknown_account_class"),
    UNKNOWN_ORIGIN("unknown_origin"),
    ORIGIN_CLASS_MISMATCH("origin_class_mismatch"),
    BAD_HOMESERVER_ID_LENGTH("bad_homeserver_id_length"),
    INVALID_HOMESERVER_ID("invalid_homeserver_id"),
    TIMESTAMP_OUT_OF_RANGE("timestamp_out_of_range"),
    WINDOW_NOT_ORDERED("window_not_ordered"),
    WINDOW_TOO_LONG("window_too_long"),
    UNKNOWN_HOMESERVER("unknown_homeserver"),
    HOMESERVER_NOT_ACTIVE("homeserver_not_active"),
    SIGNER_KEY_UNUSABLE("signer_key_unusable"),
    BAD_SIGNATURE("bad_signature"),
    NOT_YET_VALID("not_yet_valid"),
    EXPIRED("expired"),
    ISSUED_IN_THE_FUTURE("issued_in_the_future"),
    PLACEMENT_CONFLICT("placement_conflict"),
    STALE_REISSUE("stale_reissue"),
    INGEST_DISABLED("ingest_disabled");

    private final String reason;

    PlacementRecordRejection(String reason) {
        this.reason = reason;
    }

    /** The API error code and the metric tag value. */
    public String reason() {
        return reason;
    }
}
