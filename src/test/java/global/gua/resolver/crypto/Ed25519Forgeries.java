package global.gua.resolver.crypto;

import java.util.Base64;
import java.util.HexFormat;

/** Ed25519 identity-point forgery: R = identity, S = 0. */
public final class Ed25519Forgeries {

    public static final String IDENTITY_HEX = "0100000000000000000000000000000000000000000000000000000000000000";
    public static final String IDENTITY_KEY_B64 = spki(IDENTITY_HEX);
    public static final String IDENTITY_SIGNATURE_B64 = Base64.getEncoder().encodeToString(
            HexFormat.of().parseHex(IDENTITY_HEX + "00".repeat(32)));

    private Ed25519Forgeries() {}

    public static String spki(String rawKeyHex) {
        return Base64.getEncoder().encodeToString(HexFormat.of().parseHex("302a300506032b6570032100" + rawKeyHex));
    }
}
