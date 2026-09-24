/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;

import global.gua.resolver.placement.record.AccountId;

/**
 * Strict fixed-layout codec for the generation-1 published authority head, {@code gua-account-authority-head.v1}
 * (ADM-009 decision 12).
 *
 * <pre>
 * off      len   field
 * 0        4     magic "GUAH"          ASCII, also the signature domain
 * 4        1     version 0x01
 * 5        1     suite 0x01            Ed25519 with SHA-256, the same suite the chain records use
 * 6        34    accountId raw         0x01 || class || SHA-256(genesis bytes)
 * 40       32    headHash              SHA-256 over the canonical bytes of the head chain record
 * 72       8     headSeq               unsigned, 1 in the first record and one more per record
 * 80       1     n                     homeserverId length, 1 to 64
 * 81       n     homeserverId          ASCII roster id, never the Matrix domain
 * 81+n     8     issuedAt              epoch milliseconds, unsigned
 * 89+n     8     notBefore             epoch milliseconds, unsigned
 * 97+n     8     notAfter              epoch milliseconds, unsigned
 * 105+n          end
 * </pre>
 *
 * <p>Big-endian, no delimiters, one length prefix, one canonical spelling. Every malformed case is refused
 * with its own reason ({@link AccountAuthorityHeadRejection}) and none is repaired. ADM-001 L4 forbids reusing
 * another object's encoding for a new one, so this is its own layout rather than a placement record with
 * different fields, and it carries its own magic.
 *
 * <p>The layout deliberately mirrors the chain-record envelope of ADM-009 decision 2 in its first 80 bytes
 * (magic, version, suite, accountId, a 32-byte hash, an 8-byte seq). A reader that can walk a chain record can
 * read this object with the same primitives. It is still a distinct object: the magic is different, so no head
 * object can be replayed as a chain record or the reverse, and the roster membership key that signs this one
 * is not a key any chain record is ever verified under.
 *
 * <p>The homeserverId is inside the signed bytes because it is what selects the key the signature is checked
 * under. Without it the resolver would have to be told out of band whose signature to expect, which is the
 * property that lets the ingest be public and self-authenticating.
 *
 * <p>{@link #encode} exists for tests and offline tooling. The ingest path never re-encodes: it hashes,
 * verifies and stores the bytes it received, and {@link #decode} only re-derives the accountId string from the
 * raw bytes those same received bytes carry.
 */
public final class AccountAuthorityHeadCodec {

    /**
     * ASCII "GUAH". The magic is the signature domain, which is what keeps this object from being mistaken
     * for anything else a roster membership key signs: a placement record opens {@code GUAP}, a
     * {@code gua-lp.v1} object opens with a u32 length whose first byte is 0x00, and admission's bare
     * possession proof signs a server name, which cannot begin with these four bytes followed by two
     * control bytes. It is also distinct from every chain-record magic of ADM-009 decision 2
     * ({@code GUAA}, {@code GUAD}, {@code GUAX}, {@code GUAR}, {@code GUAO}).
     */
    public static final byte[] MAGIC = {'G', 'U', 'A', 'H'};

    public static final int VERSION = 0x01;

    /** Suite 0x01: Ed25519 with SHA-256, the only suite defined for framework 0x01. */
    public static final int SUITE = 0x01;

    /** The domain string this object is known by in docs and in the version-1 vectors. */
    public static final String DOMAIN = "gua-account-authority-head.v1";

    /** Everything but the homeserver id. */
    public static final int FIXED_LENGTH = 105;

    public static final int MAX_HOMESERVER_ID_LENGTH = 64;

    /** The head record hash, and the chain's prevHash, are both SHA-256. */
    public static final int HEAD_HASH_LENGTH = 32;

    /** The delimiter the transparency-log leaves are built with, so it cannot appear inside a field. */
    private static final char LEAF_DELIMITER = '|';

    private static final HexFormat HEX = HexFormat.of();

    private AccountAuthorityHeadCodec() {}

    /** Decode and structurally validate the canonical bytes; refuses with one reason per defect. */
    public static AccountAuthorityHead decode(byte[] canonical) {
        if (canonical == null
                || canonical.length < FIXED_LENGTH + 1
                || canonical.length > FIXED_LENGTH + MAX_HOMESERVER_ID_LENGTH) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.WRONG_LENGTH);
        }
        if (!Arrays.equals(Arrays.copyOfRange(canonical, 0, MAGIC.length), MAGIC)) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.BAD_MAGIC);
        }
        int version = canonical[4] & 0xFF;
        if (version != VERSION) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.UNSUPPORTED_VERSION);
        }
        int suite = canonical[5] & 0xFF;
        if (suite != SUITE) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.UNSUPPORTED_SUITE);
        }

        byte[] accountIdRaw = Arrays.copyOfRange(canonical, 6, 6 + AccountId.RAW_LENGTH);
        if (accountIdRaw[0] != AccountId.FORMAT_VERSION) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.BAD_ACCOUNT_ID_VERSION);
        }
        byte rootClass = AccountId.rootClass(accountIdRaw);
        if (rootClass != AccountId.CLASS_BOOTSTRAP && rootClass != AccountId.CLASS_GENESIS) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.UNKNOWN_ACCOUNT_CLASS);
        }

        byte[] headHash = Arrays.copyOfRange(canonical, 40, 40 + HEAD_HASH_LENGTH);
        // 32 zero bytes is the empty chain's prevHash (ADM-009 decision 2), which names no record. Publishing
        // it would anchor "this account has no head", which is not a head and is not what this leaf commits.
        if (isAllZero(headHash)) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.ZERO_HEAD_HASH);
        }

        long headSeq = readLong(canonical, 72);
        // Sequence numbers are unsigned on the wire; the first chain record is 1, so zero names no record and
        // anything that reads negative as a signed long is past every seq a chain can reach.
        if (headSeq <= 0) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.BAD_HEAD_SEQ);
        }

        int idLength = canonical[80] & 0xFF;
        if (idLength < 1 || idLength > MAX_HOMESERVER_ID_LENGTH) {
            throw new AccountAuthorityHeadException(
                    AccountAuthorityHeadRejection.BAD_HOMESERVER_ID_LENGTH);
        }
        if (canonical.length != FIXED_LENGTH + idLength) {
            throw new AccountAuthorityHeadException(
                    AccountAuthorityHeadRejection.DECLARED_LENGTH_MISMATCH);
        }
        String homeserverId = homeserverId(canonical, idLength);

        int offset = 81 + idLength;
        Instant issuedAt = instant(canonical, offset);
        Instant notBefore = instant(canonical, offset + 8);
        Instant notAfter = instant(canonical, offset + 16);
        if (!notAfter.isAfter(notBefore)) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.WINDOW_NOT_ORDERED);
        }

        return new AccountAuthorityHead(version, suite, AccountId.encode(accountIdRaw),
                HEX.formatHex(headHash), headSeq, homeserverId, issuedAt, notBefore, notAfter);
    }

    /**
     * The canonical bytes for a head object. For tests and offline signing tools only: the resolver signs no
     * head and re-encodes none, because the bytes that were signed are the bytes it received.
     */
    public static byte[] encode(AccountAuthorityHead head) {
        byte[] accountIdRaw = AccountId.decode(head.accountId());
        byte[] headHash = HEX.parseHex(head.headHashHex());
        if (headHash.length != HEAD_HASH_LENGTH) {
            throw new IllegalArgumentException("a head hash is exactly " + HEAD_HASH_LENGTH + " bytes");
        }
        byte[] homeserverId = head.homeserverId().getBytes(StandardCharsets.US_ASCII);
        if (homeserverId.length < 1 || homeserverId.length > MAX_HOMESERVER_ID_LENGTH) {
            throw new AccountAuthorityHeadException(
                    AccountAuthorityHeadRejection.BAD_HOMESERVER_ID_LENGTH);
        }
        byte[] out = new byte[FIXED_LENGTH + homeserverId.length];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        out[4] = (byte) head.version();
        out[5] = (byte) head.suite();
        System.arraycopy(accountIdRaw, 0, out, 6, accountIdRaw.length);
        System.arraycopy(headHash, 0, out, 40, headHash.length);
        putLong(out, 72, head.headSeq());
        out[80] = (byte) homeserverId.length;
        System.arraycopy(homeserverId, 0, out, 81, homeserverId.length);
        int offset = 81 + homeserverId.length;
        putLong(out, offset, head.issuedAt().toEpochMilli());
        putLong(out, offset + 8, head.notBefore().toEpochMilli());
        putLong(out, offset + 16, head.notAfter().toEpochMilli());
        return out;
    }

    private static String homeserverId(byte[] canonical, int idLength) {
        char[] chars = new char[idLength];
        for (int i = 0; i < idLength; i++) {
            int b = canonical[81 + i] & 0xFF;
            // Printable ASCII only, and never the delimiter the log leaves are built with, so one leaf string
            // can only be read one way.
            if (b <= 0x20 || b >= 0x7F || b == LEAF_DELIMITER) {
                throw new AccountAuthorityHeadException(
                        AccountAuthorityHeadRejection.INVALID_HOMESERVER_ID);
            }
            chars[i] = (char) b;
        }
        return new String(chars);
    }

    private static Instant instant(byte[] bytes, int offset) {
        long value = readLong(bytes, offset);
        // Epoch milliseconds are unsigned on the wire; anything that reads negative as a signed long is far
        // past any representable time and is refused rather than wrapped.
        if (value < 0) {
            throw new AccountAuthorityHeadException(
                    AccountAuthorityHeadRejection.TIMESTAMP_OUT_OF_RANGE);
        }
        return Instant.ofEpochMilli(value);
    }

    private static long readLong(byte[] bytes, int offset) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (bytes[offset + i] & 0xFFL);
        }
        return value;
    }

    private static void putLong(byte[] out, int offset, long value) {
        for (int i = 0; i < 8; i++) {
            out[offset + i] = (byte) (value >>> (8 * (7 - i)));
        }
    }

    private static boolean isAllZero(byte[] bytes) {
        for (byte b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
