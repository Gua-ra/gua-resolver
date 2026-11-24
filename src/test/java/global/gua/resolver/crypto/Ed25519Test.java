package global.gua.resolver.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class Ed25519Test {

    private static final byte[] MESSAGE = "gua".getBytes(StandardCharsets.UTF_8);
    private static final Ed25519.KeyPairB64 TEST1 = Rfc8032Keys.test1();

    @ParameterizedTest
    @ValueSource(strings = {
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"})
    void refusesSmallOrderKeysThatVerifyForgedSignatures(String rawHex) {
        assertThatThrownBy(() -> Ed25519.publicKey(Ed25519Forgeries.spki(rawHex)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            // y = p, y = p + 1, and x = 0 with the sign bit set
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0100000000000000000000000000000000000000000000000000000000000080",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})
    void refusesNonCanonicalKeys(String rawHex) {
        assertThatThrownBy(() -> Ed25519.publicKey(Ed25519Forgeries.spki(rawHex)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesOtherSpellingsOfAValidKey() {
        String canonical = TEST1.publicKeyB64();
        byte[] spki = Base64.getDecoder().decode(canonical);
        String nullParameters = Base64.getEncoder().encodeToString(HexFormat.of().parseHex(
                "302c300706032b65700500032100" + Rfc8032Keys.TEST1_PUBLIC_HEX));

        assertThat(Ed25519.publicKey(canonical)).isNotNull();
        assertThatThrownBy(() -> Ed25519.publicKey(canonical.replace("=", "")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Ed25519.publicKey(canonical + "\n")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Ed25519.publicKey(Base64.getUrlEncoder().encodeToString(spki)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Ed25519.publicKey(withNonZeroTrailingBits(canonical)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Ed25519.publicKey(nullParameters)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesOtherSpellingsOfAValidSignature() {
        PublicKey key = Ed25519.publicKey(TEST1.publicKeyB64());
        PrivateKey privateKey = Ed25519.privateKey(TEST1.privateKeyB64());
        String signature = Ed25519.sign(privateKey, MESSAGE);

        assertThat(Ed25519.verify(key, MESSAGE, signature)).isTrue();
        assertThat(Ed25519.verify(key, MESSAGE, signature.replace("=", ""))).isFalse();
        assertThat(Ed25519.verify(key, MESSAGE, signature + "=")).isFalse();
        assertThat(Ed25519.verify(key, MESSAGE, withNonZeroTrailingBits(signature))).isFalse();
    }

    /** Sets the unused low bits of the last base64 digit, which a lenient decoder silently drops. */
    private static String withNonZeroTrailingBits(String padded) {
        int last = padded.replace("=", "").length() - 1;
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        char bumped = alphabet.charAt(alphabet.indexOf(padded.charAt(last)) + 1);
        return padded.substring(0, last) + bumped + padded.substring(last + 1);
    }
}
