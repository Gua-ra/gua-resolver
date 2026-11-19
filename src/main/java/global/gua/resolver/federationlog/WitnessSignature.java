package global.gua.resolver.federationlog;

import java.time.Instant;

import global.gua.resolver.crypto.CanonicalEncoder;

/** A witness's statement that it verified a checkpoint. {@code signatureB64} is outside the canonical bytes. */
public record WitnessSignature(
        String schema,
        String checkpointHash,
        String keyId,
        Instant signedAt,
        String signatureB64) {

    public static final String SCHEMA = "gua-witness-signature.v1";

    public void validateShape() {
        if (!SCHEMA.equals(schema)) {
            throw new FederationLogException("unsupported witness signature schema: " + schema);
        }
        Checks.sha256Hex(checkpointHash, "checkpointHash");
        if (keyId == null || keyId.isBlank()) {
            throw new FederationLogException("keyId is required");
        }
        Checks.millis(signedAt, "signedAt");
    }

    public byte[] canonicalBytes() {
        if (signedAt == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("signedAt is required");
        }
        return CanonicalEncoder.begin(SCHEMA)
                .string(checkpointHash)
                .string(keyId)
                .int64(signedAt.toEpochMilli())
                .toByteArray();
    }
}
