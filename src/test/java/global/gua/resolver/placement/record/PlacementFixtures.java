package global.gua.resolver.placement.record;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import global.gua.resolver.admission.AdmissionRequest;
import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.crypto.Ed25519;

/**
 * Builders for placement-record tests. Every key here is minted in memory for the test that uses it and
 * nothing real is ever signed with one. The accountIds are derived from a test seed, so they are stable and
 * readable in failures while carrying nothing that could belong to an account.
 */
final class PlacementFixtures {

    /** Comfortably inside the 400-day cap so the window itself is never what a test is refused for. */
    static final Duration VALIDITY = Duration.ofDays(399);

    private PlacementFixtures() {}

    /** A deterministic accountId of the given root class. */
    static String accountId(byte rootClass, String seed) {
        byte[] raw = new byte[AccountId.RAW_LENGTH];
        raw[0] = AccountId.FORMAT_VERSION;
        raw[1] = rootClass;
        System.arraycopy(sha256(seed), 0, raw, 2, 32);
        return AccountId.encode(raw);
    }

    /** A genesis-rooted accountId. */
    static String genesisAccountId(String seed) {
        return accountId(AccountId.CLASS_GENESIS, seed);
    }

    /** A bootstrap accountId. */
    static String bootstrapAccountId(String seed) {
        return accountId(AccountId.CLASS_BOOTSTRAP, seed);
    }

    /** A well-formed generation-1 record whose origin matches the id's class and whose window holds now. */
    static PlacementRecord record(String accountId, String homeserverId, Instant issuedAt) {
        PlacementRecord.Origin origin = PlacementRecord.Origin.of(AccountId.decode(accountId)[1]);
        return new PlacementRecord(PlacementRecordCodec.VERSION, PlacementRecordCodec.GENERATION,
                accountId, origin, homeserverId, issuedAt, issuedAt, issuedAt.plus(VALIDITY));
    }

    static byte[] canonical(String accountId, String homeserverId, Instant issuedAt) {
        return PlacementRecordCodec.encode(record(accountId, homeserverId, issuedAt));
    }

    static String recordB64(byte[] canonical) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(canonical);
    }

    static String sign(byte[] canonical, Ed25519.KeyPairB64 key) {
        return Ed25519.sign(Ed25519.privateKey(key.privateKeyB64()), canonical);
    }

    /** The transport envelope as JSON: the canonical bytes base64url, the detached signature base64. */
    static String envelope(byte[] canonical, Ed25519.KeyPairB64 key) {
        return envelope(recordB64(canonical), sign(canonical, key));
    }

    static String envelope(String recordB64, String signatureB64) {
        return "{\"record\":\"" + recordB64 + "\",\"signature\":\"" + signatureB64 + "\"}";
    }

    /** Admit a homeserver on the legacy path: a possession proof over its own server name. */
    static void admit(AdmissionService admission, String id, String serverName, Ed25519.KeyPairB64 key) {
        String proof = Ed25519.sign(Ed25519.privateKey(key.privateKeyB64()),
                serverName.getBytes(StandardCharsets.UTF_8));
        admission.admit(new AdmissionRequest(id, serverName, "https://" + serverName,
                "https://account." + serverName, "BR", 1, true, key.publicKeyB64(), proof,
                "dns-txt-proof-token", List.of(), null, null));
    }

    private static byte[] sha256(String seed) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(seed.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
