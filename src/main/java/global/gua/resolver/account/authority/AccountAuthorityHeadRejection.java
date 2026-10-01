/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

/**
 * Every way a published authority head, or a verification of one, can be refused, one reason each.
 *
 * <p>The reason is the API error code and the {@code reason} tag on
 * {@code gua.resolver.account.authority.head.rejections}, so a refusal is countable and attributable without
 * reading logs. A refusal never carries anything the caller sent back to it.
 *
 * <p>The order below is the order the checks run in, and that order is load-bearing, exactly as it is for
 * placement records. Everything above {@link #BAD_SIGNATURE} is a property of the bytes the caller presented
 * and consults no stored state, so the two answers that describe stored state ({@link #AUTHORITY_CONFLICT},
 * {@link #STALE_HEAD}) are unreachable without the roster signing key of an ACTIVE member. That is what keeps
 * the public ingest from being an oracle for which accounts this node holds heads for.
 *
 * <p>The tail of the enum belongs to the reader rather than to the ingest: those are the reasons the library
 * verifier refuses a head it was shown, and they never occur on the ingest path.
 */
public enum AccountAuthorityHeadRejection {

    /** The transport envelope is missing a field or is not the expected JSON object. */
    MALFORMED_ENVELOPE("malformed_envelope"),

    /** The record field is not the one unpadded base64url spelling of the bytes it decodes to. */
    BAD_BASE64("bad_base64"),

    /** The byte string is outside the possible length range for any version-1 head object. */
    WRONG_LENGTH("wrong_length"),

    /** The length does not match the one the homeserver-id length prefix declares (truncated or trailing). */
    DECLARED_LENGTH_MISMATCH("declared_length_mismatch"),

    /** The first four bytes are not the ASCII magic, which is also the signature domain. */
    BAD_MAGIC("bad_magic"),

    /** A head-object version this build does not decode. */
    UNSUPPORTED_VERSION("unsupported_version"),

    /** A signature suite other than 0x01 (Ed25519 with SHA-256). */
    UNSUPPORTED_SUITE("unsupported_suite"),

    /** The first raw accountId byte is not the accountId format version. */
    BAD_ACCOUNT_ID_VERSION("bad_account_id_version"),

    /** The accountId root class byte is neither bootstrap nor genesis. */
    UNKNOWN_ACCOUNT_CLASS("unknown_account_class"),

    /** The head hash is 32 zero bytes, which is the empty chain: there is no head to publish. */
    ZERO_HEAD_HASH("zero_head_hash"),

    /** The head sequence number is zero or negative as an unsigned 64-bit value; the first record is 1. */
    BAD_HEAD_SEQ("bad_head_seq"),

    /** The declared homeserver-id length is zero or above the maximum. */
    BAD_HOMESERVER_ID_LENGTH("bad_homeserver_id_length"),

    /** The homeserver id is not printable ASCII, or carries the character the log leaves delimit on. */
    INVALID_HOMESERVER_ID("invalid_homeserver_id"),

    /** A timestamp is outside the range an epoch-millisecond instant can hold. */
    TIMESTAMP_OUT_OF_RANGE("timestamp_out_of_range"),

    /** notAfter does not follow notBefore. */
    WINDOW_NOT_ORDERED("window_not_ordered"),

    /** The validity window is longer than the configured maximum. */
    WINDOW_TOO_LONG("window_too_long"),

    /** The object names a homeserver that is not in the roster at all. */
    UNKNOWN_HOMESERVER("unknown_homeserver"),

    /** The object names a roster entry that is not ACTIVE, including one that used to be. */
    HOMESERVER_NOT_ACTIVE("homeserver_not_active"),

    /** The named entry's roster signing key is not a usable Ed25519 public key. */
    SIGNER_KEY_UNUSABLE("signer_key_unusable"),

    /** The signature does not verify under the roster key of the homeserver the object names. */
    BAD_SIGNATURE("bad_signature"),

    /** notBefore is still ahead of the reader's clock, beyond the accepted skew. */
    NOT_YET_VALID("not_yet_valid"),

    /** notAfter is behind the reader's clock, beyond the accepted skew: a stale head, not a wrong one. */
    EXPIRED("expired"),

    /** issuedAt is ahead of the reader's clock, beyond the accepted skew, so it cannot freeze a slot. */
    ISSUED_IN_THE_FUTURE("issued_in_the_future"),

    /**
     * A different homeserver already published a head for this accountId. One account has one home
     * (ADM-001 L9), so a second homeserver's head is refused, never migrated and never held beside the first.
     */
    AUTHORITY_CONFLICT("authority_conflict"),

    /**
     * A placement record this node holds names a different homeserver for this accountId. Only checked while
     * placement custody is on; it is the one piece of independent entitlement evidence the resolver has.
     */
    PLACEMENT_DISAGREES("placement_disagrees"),

    /** The publishing homeserver presented a head sequence number that is not newer than the stored one. */
    STALE_HEAD("stale_head"),

    /** The ingest flag is off; reads are unaffected. */
    INGEST_DISABLED("ingest_disabled"),

    /** The stored head has no log leaf yet, so there is nothing to prove inclusion of. */
    HEAD_NOT_ANCHORED("head_not_anchored"),

    // --- reader side only: the library verifier's refusals ---

    /** The roster the head was verified against does not carry k valid authority signatures. */
    ROSTER_UNVERIFIED("roster_unverified"),

    /** The proof names a leaf that is not an ACCOUNT_AUTHORITY leaf. */
    LEAF_TYPE_MISMATCH("leaf_type_mismatch"),

    /** The leaf was published by a homeserver other than the one that signed the head object. */
    LEAF_PUBLISHER_MISMATCH("leaf_publisher_mismatch"),

    /** The leaf's payload hash is not the SHA-256 of the head bytes presented with it. */
    PAYLOAD_HASH_MISMATCH("payload_hash_mismatch"),

    /** The served leaf hash is not the hash of the leaf's own fields, so the proof describes nothing. */
    LEAF_HASH_MISMATCH("leaf_hash_mismatch"),

    /** The audit path does not place that leaf in the tree the checkpoint's root names. */
    LEAF_NOT_INCLUDED("leaf_not_included"),

    /** The checkpoint the proof was computed against is not the signed one and was not shown to precede it. */
    CHECKPOINT_NOT_EXTENDED("checkpoint_not_extended"),

    /** The head object is for a different account than the one being verified. */
    ACCOUNT_MISMATCH("account_mismatch"),

    /** The published head hash is not the one the account's own homeserver just served. */
    HEAD_HASH_MISMATCH("head_hash_mismatch"),

    /** The published head sequence number is not the one the account's own homeserver just served. */
    HEAD_SEQ_MISMATCH("head_seq_mismatch");

    private final String reason;

    AccountAuthorityHeadRejection(String reason) {
        this.reason = reason;
    }

    /** The stable code: the API error code and the metric tag value. */
    public String reason() {
        return reason;
    }
}
