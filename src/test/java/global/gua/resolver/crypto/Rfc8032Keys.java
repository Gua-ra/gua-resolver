package global.gua.resolver.crypto;

import java.util.Base64;
import java.util.HexFormat;

/** RFC 8032 section 7.1 test keys: published constants, never used to sign anything real. */
public final class Rfc8032Keys {

    public static final String TEST1_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    public static final String TEST1_PUBLIC_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    public static final String TEST2_SEED_HEX = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    public static final String TEST2_PUBLIC_HEX = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    public static final String TEST3_SEED_HEX = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    public static final String TEST3_PUBLIC_HEX = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    public static final String TEST1024_SEED_HEX = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5";
    public static final String TEST1024_PUBLIC_HEX = "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e";
    public static final String TEST_SHA_ABC_SEED_HEX = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
    public static final String TEST_SHA_ABC_PUBLIC_HEX = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";

    private static final String SPKI_PREFIX = "302a300506032b6570032100";
    private static final String PKCS8_PREFIX = "302e020100300506032b657004220420";

    private Rfc8032Keys() {}

    public static Ed25519.KeyPairB64 test1() {
        return pair(TEST1_SEED_HEX, TEST1_PUBLIC_HEX);
    }

    public static Ed25519.KeyPairB64 test2() {
        return pair(TEST2_SEED_HEX, TEST2_PUBLIC_HEX);
    }

    public static Ed25519.KeyPairB64 test3() {
        return pair(TEST3_SEED_HEX, TEST3_PUBLIC_HEX);
    }

    public static Ed25519.KeyPairB64 test1024() {
        return pair(TEST1024_SEED_HEX, TEST1024_PUBLIC_HEX);
    }

    public static Ed25519.KeyPairB64 testShaAbc() {
        return pair(TEST_SHA_ABC_SEED_HEX, TEST_SHA_ABC_PUBLIC_HEX);
    }

    public static Ed25519.KeyPairB64 pair(String seedHex, String publicHex) {
        HexFormat hex = HexFormat.of();
        Base64.Encoder b64 = Base64.getEncoder();
        return new Ed25519.KeyPairB64(
                b64.encodeToString(hex.parseHex(SPKI_PREFIX + publicHex)),
                b64.encodeToString(hex.parseHex(PKCS8_PREFIX + seedHex)));
    }
}
