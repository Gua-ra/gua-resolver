package global.gua.resolver.placement.record;

/**
 * The transport form of a placement record: the canonical bytes and the detached signature over them.
 *
 * <p>{@code record} is the canonical byte string, base64url without padding. {@code signature} is the
 * Ed25519 signature over those exact bytes, base64. The resolver stores both strings verbatim and serves
 * them back unchanged, so a reader verifies the bytes the signer signed rather than a re-encoding of a
 * parsed object (ADM-001 L4: hash and verify the bytes that crossed the wire).
 */
public record PlacementRecordEnvelope(String record, String signature) {}
