/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import global.gua.resolver.admission.AdmissionRequest;
import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.placement.record.AccountId;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLeaf;
import global.gua.resolver.roster.TransparencyLog;

/**
 * Builders for published-authority-head tests. Every key here is minted in memory for the test that uses it and
 * nothing real is ever signed with one. The accountIds and head hashes are derived from a test seed, so they are
 * stable and readable in failures while carrying nothing that could belong to an account.
 */
public final class AuthorityHeadFixtures {

    /** Comfortably inside the 400-day cap so the window itself is never what a test is refused for. */
    public static final Duration VALIDITY = Duration.ofDays(399);

    private static final HexFormat HEX = HexFormat.of();

    private AuthorityHeadFixtures() {}

    /** A deterministic accountId of the given root class. */
    public static String accountId(byte rootClass, String seed) {
        byte[] raw = new byte[AccountId.RAW_LENGTH];
        raw[0] = AccountId.FORMAT_VERSION;
        raw[1] = rootClass;
        System.arraycopy(sha256(seed), 0, raw, 2, 32);
        return AccountId.encode(raw);
    }

    /** A bootstrap accountId: the class ADM-009 decision 12 is written about. */
    public static String bootstrapAccountId(String seed) {
        return accountId(AccountId.CLASS_BOOTSTRAP, seed);
    }

    public static String genesisAccountId(String seed) {
        return accountId(AccountId.CLASS_GENESIS, seed);
    }

    /** A deterministic 32-byte chain-record hash, hex. */
    public static String headHash(String seed) {
        return HEX.formatHex(sha256(seed));
    }

    /** A well-formed head object whose window holds at {@code issuedAt}. */
    public static AccountAuthorityHead head(String accountId, String headHashHex, long headSeq,
                                            String homeserverId, Instant issuedAt) {
        return new AccountAuthorityHead(AccountAuthorityHeadCodec.VERSION,
                AccountAuthorityHeadCodec.SUITE, accountId, headHashHex, headSeq, homeserverId,
                issuedAt, issuedAt, issuedAt.plus(VALIDITY));
    }

    public static byte[] canonical(String accountId, String headHashHex, long headSeq, String homeserverId,
                                   Instant issuedAt) {
        return AccountAuthorityHeadCodec.encode(
                head(accountId, headHashHex, headSeq, homeserverId, issuedAt));
    }

    public static String recordB64(byte[] canonical) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(canonical);
    }

    public static String sign(byte[] canonical, Ed25519.KeyPairB64 key) {
        return Ed25519.sign(Ed25519.privateKey(key.privateKeyB64()), canonical);
    }

    public static AccountAuthorityHeadEnvelope envelope(byte[] canonical, Ed25519.KeyPairB64 key) {
        return new AccountAuthorityHeadEnvelope(recordB64(canonical), sign(canonical, key));
    }

    /** The transport envelope as JSON, for the ingest endpoint. */
    public static String envelopeJson(byte[] canonical, Ed25519.KeyPairB64 key) {
        return json(recordB64(canonical), sign(canonical, key));
    }

    public static String json(String recordB64, String signatureB64) {
        return "{\"record\":\"" + recordB64 + "\",\"signature\":\"" + signatureB64 + "\"}";
    }

    /** Admit a homeserver on the legacy path: a possession proof over its own server name. */
    public static void admit(AdmissionService admission, String id, String serverName,
                             Ed25519.KeyPairB64 key) {
        String proof = Ed25519.sign(Ed25519.privateKey(key.privateKeyB64()),
                serverName.getBytes(StandardCharsets.UTF_8));
        admission.admit(new AdmissionRequest(id, serverName, "https://" + serverName,
                "https://account." + serverName, "BR", 1, true, key.publicKeyB64(), proof,
                "dns-txt-proof-token", List.of(), null, null));
    }

    /**
     * An in-memory stand-in for the transparency log's tree, so a test can build a log that carries a leaf, a
     * log that does not, and the proofs either way, without a database. It hashes leaves through the same
     * {@link TransparencyLeaf} function the real log appends with, which is the point: a fixture that computed
     * leaf hashes its own way would prove nothing about the server.
     */
    public static final class FakeLog {

        private final List<String> leafHashes = new ArrayList<>();
        private final List<AccountAuthorityHeadProof.Leaf> leaves = new ArrayList<>();

        /** Append a leaf of any type and return its index. */
        public long append(String type, String publisherId, String payloadHash, long recordedAtMillis) {
            long index = leafHashes.size();
            String leafHash = TransparencyLeaf.hash(index, type, publisherId, payloadHash,
                    recordedAtMillis);
            leafHashes.add(leafHash);
            leaves.add(new AccountAuthorityHeadProof.Leaf(index, type, publisherId, payloadHash,
                    recordedAtMillis, leafHash));
            return index;
        }

        /** Append the ACCOUNT_AUTHORITY leaf for these head bytes and return its index. */
        public long appendHead(byte[] canonical, String publisherId, Instant recordedAt) {
            return append(TransparencyLog.ACCOUNT_AUTHORITY, publisherId,
                    MerkleTree.sha256Hex(canonical), recordedAt.toEpochMilli());
        }

        public AccountAuthorityHeadProof.Leaf leaf(long index) {
            return leaves.get((int) index);
        }

        public SignedRoster.LogCheckpoint checkpoint() {
            return checkpoint(leafHashes.size());
        }

        /** The checkpoint at an earlier tree size, for the case where the log moved between two requests. */
        public SignedRoster.LogCheckpoint checkpoint(int size) {
            return new SignedRoster.LogCheckpoint(
                    MerkleTree.root(leafHashes.subList(0, size)), size);
        }

        public List<String> auditPath(long index) {
            return auditPath(index, leafHashes.size());
        }

        public List<String> auditPath(long index, int size) {
            return MerkleTree.inclusionProof(leafHashes.subList(0, size), (int) index);
        }

        public List<String> consistencyProof(int first, int second) {
            return MerkleTree.consistencyProof(leafHashes, first, second);
        }

        public int size() {
            return leafHashes.size();
        }
    }

    private static byte[] sha256(String seed) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(seed.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
