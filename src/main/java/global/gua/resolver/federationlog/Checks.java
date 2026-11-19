package global.gua.resolver.federationlog;

import java.time.Instant;
import java.util.Base64;
import java.util.regex.Pattern;

import global.gua.resolver.crypto.CanonicalEncoder.CanonicalEncodingException;

final class Checks {

    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-f]{64}");
    private static final int ED25519_SIGNATURE_BYTES = 64;

    private Checks() {}

    static void sha256Hex(String value, String field) {
        if (value == null || !SHA256_HEX.matcher(value).matches()) {
            throw new FederationLogException(field + " must be 64 lowercase hex characters");
        }
    }

    static void millis(Instant value, String field) {
        if (value == null || value.getNano() % 1_000_000 != 0) {
            throw new FederationLogException(field + " is required at millisecond precision");
        }
    }

    static byte[] signatureBytes(String signatureB64) {
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(signatureB64 == null ? "" : signatureB64);
        } catch (IllegalArgumentException e) {
            throw new CanonicalEncodingException("signature is not base64");
        }
        if (raw.length != ED25519_SIGNATURE_BYTES) {
            throw new CanonicalEncodingException("an Ed25519 signature is 64 bytes");
        }
        return raw;
    }
}
