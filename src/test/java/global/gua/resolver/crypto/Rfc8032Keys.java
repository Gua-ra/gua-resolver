package global.gua.resolver.crypto;

import java.util.Base64;
import java.util.HexFormat;

/**
 * The RFC 8032 section 7.1 TEST 1 and TEST 2 Ed25519 keys, rebuilt in memory as the base64 X.509 / PKCS#8
 * forms {@link Ed25519} uses. They are published test constants, which is why the golden vectors can carry
 * reproducible signatures; nothing real is ever signed with them.
 */
public final class Rfc8032Keys {

    public static final String TEST1_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    public static final String TEST1_PUBLIC_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    public static final String TEST2_SEED_HEX = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    public static final String TEST2_PUBLIC_HEX = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

    private static final String SPKI_PREFIX = "302a300506032b6570032100";
    private static final String PKCS8_PREFIX = "302e020100300506032b657004220420";

    private Rfc8032Keys() {}

    public static Ed25519.KeyPairB64 test1() {
        return pair(TEST1_SEED_HEX, TEST1_PUBLIC_HEX);
    }

    public static Ed25519.KeyPairB64 test2() {
        return pair(TEST2_SEED_HEX, TEST2_PUBLIC_HEX);
    }

    public static Ed25519.KeyPairB64 pair(String seedHex, String publicHex) {
        HexFormat hex = HexFormat.of();
        Base64.Encoder b64 = Base64.getEncoder();
        return new Ed25519.KeyPairB64(
                b64.encodeToString(hex.parseHex(SPKI_PREFIX + publicHex)),
                b64.encodeToString(hex.parseHex(PKCS8_PREFIX + seedHex)));
    }
}
