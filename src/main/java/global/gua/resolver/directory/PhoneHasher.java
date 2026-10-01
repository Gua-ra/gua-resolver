package global.gua.resolver.directory;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;

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
