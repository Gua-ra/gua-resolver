package global.gua.resolver.directory;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;

/**
 * Turns an E.164 phone number into the peppered HMAC under which it is stored/looked up in the shared
 * directory (§4). The raw number is never persisted or logged; lookups require the shared pepper, so the
 * table is useless for enumeration if exfiltrated and cannot be reversed without the secret. The pepper
 * MUST be identical across the resolver fleet AND identity-service (which writes the entries).
 */
@Component
public class PhoneHasher {

    private static final HexFormat HEX = HexFormat.of();
    private final byte[] pepper;

    public PhoneHasher(ResolverProperties props) {
        String p = props.getDirectory().getPepper();
        if (p == null || p.isBlank()) {
            throw new IllegalStateException(
                    "gua.resolver.directory.pepper is required (shared with identity-service)");
        }
        this.pepper = p.getBytes(StandardCharsets.UTF_8);
    }

    /** Peppered HMAC-SHA256 (hex) of a normalized E.164 phone. */
    public String hashPhone(String e164) {
        return hmacHex("phone:" + normalize(e164));
    }

    private static String normalize(String e164) {
        if (e164 == null) {
            throw new IllegalArgumentException("phone required");
        }
        String trimmed = e164.trim();
        if (!trimmed.matches("\\+[1-9]\\d{6,14}")) {
            throw new IllegalArgumentException("phone must be E.164 (e.g. +5511987654321)");
        }
        return trimmed;
    }

    private String hmacHex(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepper, "HmacSHA256"));
            return HEX.formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC failure", e);
        }
    }
}
