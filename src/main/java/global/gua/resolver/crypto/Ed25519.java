package global.gua.resolver.crypto;

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
import java.util.Base64;

/**
 * Thin, dependency-free wrapper over the JDK-native Ed25519 provider (JDK 15+). Used for both directory-
 * authority roster signatures (§5) and homeserver membership credentials (the roster-anchored signing key).
 *
 * <p>Keys are exchanged as base64: public keys as X.509 {@code SubjectPublicKeyInfo}, private keys as
 * PKCS#8. {@link #generate()} is for tests/bootstrap key generation.
 */
public final class Ed25519 {

    private static final String ALG = "Ed25519";
    private static final Base64.Encoder B64E = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private Ed25519() {}

    public record KeyPairB64(String publicKeyB64, String privateKeyB64) {}

    /** Generate a fresh Ed25519 keypair, encoded base64 (X.509 public, PKCS#8 private). */
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

    public static PublicKey publicKey(String base64X509) {
        try {
            return KeyFactory.getInstance(ALG)
                    .generatePublic(new X509EncodedKeySpec(B64D.decode(base64X509)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IllegalArgumentException e) {
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

    /** Sign {@code message}, returning the detached signature base64-encoded. */
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

    /** Verify a base64 detached signature over {@code message}. Returns false on any malformed input. */
    public static boolean verify(PublicKey key, byte[] message, String signatureB64) {
        try {
            Signature s = Signature.getInstance(ALG);
            s.initVerify(key);
            s.update(message);
            return s.verify(B64D.decode(signatureB64));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException
                 | IllegalArgumentException e) {
            return false;
        }
    }
}
