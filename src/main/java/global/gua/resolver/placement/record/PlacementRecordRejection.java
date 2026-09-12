package global.gua.resolver.placement.record;

/**
 * Every way a placement record can be refused, one reason each.
 *
 * <p>The reason is the API error code and the {@code reason} tag on
 * {@code gua_resolver_placement_record_rejections_total}, so a rejection is countable and attributable
 * without reading logs. A refusal never carries anything the caller sent back to it.
 *
 * <p>The order below is the order the checks run in, and that order is load-bearing. Everything above
 * {@link #BAD_SIGNATURE} is a property of the bytes the caller presented; nothing above it consults stored
 * state. Only a record that verifies under the roster key of the ACTIVE homeserver it names reaches the
 * storage rules, so the two answers that describe stored state ({@link #PLACEMENT_CONFLICT},
 * {@link #STALE_REISSUE}) are unreachable without a member key. That is what keeps the public ingest from
 * being an oracle for what is already stored.
 */
public enum PlacementRecordRejection {

    /** The transport envelope is missing a field or is not the expected JSON object. */
    MALFORMED_ENVELOPE("malformed_envelope"),

    /** The record field is not unpadded base64url. */
    BAD_BASE64("bad_base64"),

    /** The byte string is outside the possible length range for any version-1 record. */
    WRONG_LENGTH("wrong_length"),

    /** The length does not match the one the homeserver-id length prefix declares (truncated or trailing). */
    DECLARED_LENGTH_MISMATCH("declared_length_mismatch"),

    /** The first four bytes are not the ASCII magic, which is also the signature domain. */
    BAD_MAGIC("bad_magic"),

    /** A record version this build does not decode. */
    UNSUPPORTED_VERSION("unsupported_version"),

    /** A generation other than 1. Generation 1 is all this phase issues or accepts. */
    UNSUPPORTED_GENERATION("unsupported_generation"),

    /** The first raw accountId byte is not the accountId format version. */
    BAD_ACCOUNT_ID_VERSION("bad_account_id_version"),

    /** The accountId root class byte is neither bootstrap nor genesis. */
    UNKNOWN_ACCOUNT_CLASS("unknown_account_class"),

    /** The origin byte is neither bootstrap nor genesis. */
    UNKNOWN_ORIGIN("unknown_origin"),

    /** The origin byte disagrees with the class byte inside the accountId it names. */
    ORIGIN_CLASS_MISMATCH("origin_class_mismatch"),

    /** The declared homeserver-id length is zero or above the maximum. */
    BAD_HOMESERVER_ID_LENGTH("bad_homeserver_id_length"),

    /** The homeserver id is not printable ASCII, or carries the character the checkpoint leaves delimit on. */
    INVALID_HOMESERVER_ID("invalid_homeserver_id"),

    /** A timestamp is outside the range an epoch-millisecond instant can hold. */
    TIMESTAMP_OUT_OF_RANGE("timestamp_out_of_range"),

    /** notAfter does not follow notBefore. */
    WINDOW_NOT_ORDERED("window_not_ordered"),

    /** The validity window is longer than the configured maximum. */
    WINDOW_TOO_LONG("window_too_long"),

    /** The record names a homeserver that is not in the roster at all. */
    UNKNOWN_HOMESERVER("unknown_homeserver"),

    /** The record names a roster entry that is not ACTIVE, including one that used to be. */
    HOMESERVER_NOT_ACTIVE("homeserver_not_active"),

    /** The named entry's roster signing key is not a usable Ed25519 public key. */
    SIGNER_KEY_UNUSABLE("signer_key_unusable"),

    /** The signature does not verify under the roster key of the homeserver the record names. */
    BAD_SIGNATURE("bad_signature"),

    /** notBefore is still ahead of this node's clock, beyond the accepted skew. */
    NOT_YET_VALID("not_yet_valid"),

    /** notAfter is behind this node's clock, beyond the accepted skew. */
    EXPIRED("expired"),

    /** issuedAt is ahead of this node's clock, beyond the accepted skew, so it cannot freeze a slot. */
    ISSUED_IN_THE_FUTURE("issued_in_the_future"),

    /** A different homeserver already holds this accountId. One accountId has one home (ADM-001 L9). */
    PLACEMENT_CONFLICT("placement_conflict"),

    /** The holding homeserver re-issued with an issuedAt that is not newer than the stored one. */
    STALE_REISSUE("stale_reissue"),

    /** The ingest flag is off; reads are unaffected. */
    INGEST_DISABLED("ingest_disabled");

    private final String reason;

    PlacementRecordRejection(String reason) {
        this.reason = reason;
    }

    /** The stable code: the API error code and the metric tag value. */
    public String reason() {
        return reason;
    }
}
