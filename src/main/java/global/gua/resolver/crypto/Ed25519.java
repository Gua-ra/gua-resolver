package global.gua.resolver.crypto;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Set;

/**
 * Ed25519 over the JDK provider. Public keys are the 44-byte X.509 {@code SubjectPublicKeyInfo} and
 * signatures the raw 64 bytes, both as standard padded base64; private keys are base64 PKCS#8.
 */
public final class Ed25519 {

    private static final String ALG = "Ed25519";
    private static final Base64.Encoder B64E = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final int RAW_KEY_LENGTH = 32;
    private static final int SIGNATURE_LENGTH = 64;
    private static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    /** The y-coordinates of the eight points of order 1, 2, 4 and 8, little-endian hex, sign bit clear. */
    private static final Set<String> SMALL_ORDER_Y = Set.of(
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");

    private Ed25519() {}

    public record KeyPairB64(String publicKeyB64, String privateKeyB64) {}

    public static KeyPairB64 generate() {
        try {
            KeyPair kp = KeyPairGenerator.getInstance(ALG).generateKeyPair();
            return new KeyPairB64(
                    B64E.encodeToString(kp.getPublic().getEncoded()),
                    B64E.encodeToString(kp.getPrivate().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Ed25519 unavailable in this JVM", e);
        }
    }

    /** Refuses non-canonical encodings and small-order points, under which anyone can forge signatures. */
    public static PublicKey publicKey(String base64X509) {
        byte[] spki = decodeCanonical(base64X509);
        if (spki == null || spki.length != SPKI_PREFIX.length + RAW_KEY_LENGTH
                || !Arrays.equals(spki, 0, SPKI_PREFIX.length, SPKI_PREFIX, 0, SPKI_PREFIX.length)) {
            throw new IllegalArgumentException("invalid Ed25519 public key");
        }
        if (isNonCanonicalOrSmallOrder(Arrays.copyOfRange(spki, SPKI_PREFIX.length, spki.length))) {
            throw new IllegalArgumentException("Ed25519 public key is non-canonical or of small order");
        }
        try {
            PublicKey key = KeyFactory.getInstance(ALG).generatePublic(new X509EncodedKeySpec(spki));
            // The JDK decodes the point only when a verifier is initialised.
            Signature.getInstance(ALG).initVerify(key);
            return key;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
            throw new IllegalArgumentException("invalid Ed25519 public key", e);
        }
    }

    public static PrivateKey privateKey(String base64Pkcs8) {
        try {
            return KeyFactory.getInstance(ALG)
                    .generatePrivate(new PKCS8EncodedKeySpec(B64D.decode(base64Pkcs8)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid Ed25519 private key", e);
        }
    }

    public static String sign(PrivateKey key, byte[] message) {
        try {
            Signature s = Signature.getInstance(ALG);
            s.initSign(key);
            s.update(message);
            return B64E.encodeToString(s.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }

    /** Returns false on any malformed input. */
    public static boolean verify(PublicKey key, byte[] message, String signatureB64) {
        if (key == null) {
            return false;
        }
        byte[] signature = decodeCanonical(signatureB64);
        if (signature == null || signature.length != SIGNATURE_LENGTH) {
            return false;
        }
        try {
            Signature s = Signature.getInstance(ALG);
            s.initVerify(key);
            s.update(message);
            return s.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException
                 | IllegalArgumentException | NullPointerException e) {
            return false;
        }
    }

    /** Accepts only standard padded base64 with zero trailing bits, the one spelling every Gua verifier reads. */
    private static byte[] decodeCanonical(String base64) {
        if (base64 == null) {
            return null;
        }
        try {
            byte[] bytes = B64D.decode(base64);
            return B64E.encodeToString(bytes).equals(base64) ? bytes : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean isNonCanonicalOrSmallOrder(byte[] raw) {
        byte[] y = raw.clone();
        y[RAW_KEY_LENGTH - 1] &= 0x7f;
        byte[] bigEndian = new byte[RAW_KEY_LENGTH];
        for (int i = 0; i < RAW_KEY_LENGTH; i++) {
            bigEndian[i] = y[RAW_KEY_LENGTH - 1 - i];
        }
        return new BigInteger(1, bigEndian).compareTo(P) >= 0
                || SMALL_ORDER_Y.contains(HexFormat.of().formatHex(y));
    }
}
