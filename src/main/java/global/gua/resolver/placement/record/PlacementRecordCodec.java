package global.gua.resolver.placement.record;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;

/**
 * Strict fixed-layout codec for the generation-1 placement record (ADM-008 encoding tables).
 *
 * <pre>
 * off     len   field
 * 0       4     magic "GUAP"          ASCII, also the signature domain
 * 4       1     version 0x01
 * 5       1     generation 0x01
 * 6       34    accountId raw         0x01 || class || SHA-256(genesis bytes)
 * 40      1     origin                0x00 bootstrap | 0x01 genesis; equals the class byte at offset 7
 * 41      1     n                     homeserverId length, 1 to 64
 * 42      n     homeserverId          ASCII roster id, never the Matrix domain
 * 42+n    8     issuedAt              epoch milliseconds, unsigned
 * 50+n    8     notBefore             epoch milliseconds, unsigned
 * 58+n    8     notAfter              epoch milliseconds, unsigned
 * 66+n          end
 * </pre>
 *
 * <p>Big-endian, no delimiters, one length prefix. Every malformed case is refused with its own reason
 * ({@link PlacementRecordRejection}) and none is repaired.
 *
 * <p>The decode is pure: no clock, no database, no roster. Everything that depends on this node's state
 * lives in {@link PlacementRecordVerifier}, which is why a decode result can be trusted to say nothing about
 * what the resolver holds.
 *
 * <p>{@link #encode} exists for tests and for offline tooling. The ingest path never re-encodes: it hashes,
 * verifies and stores the bytes it received, and {@link #decode} only re-derives the accountId string from
 * the raw bytes those same received bytes carry.
 */
public final class PlacementRecordCodec {

    /** ASCII "GUAP". The magic is the signature domain, which is what keeps a record from being mistaken
     * for any other object a roster membership key signs: a {@code gua-lp.v1} object opens with a u32 length
     * whose first byte is 0x00, and admission's bare possession proof signs a server name, which cannot
     * begin with these four bytes followed by two control bytes. */
    public static final byte[] MAGIC = {'G', 'U', 'A', 'P'};

    public static final int VERSION = 0x01;
    public static final int GENERATION = 0x01;

    /** Everything but the homeserver id. */
    public static final int FIXED_LENGTH = 66;

    public static final int MAX_HOMESERVER_ID_LENGTH = 64;

    /** The delimiter the transparency-log checkpoint leaves use, so it cannot appear inside a field. */
    private static final char LEAF_DELIMITER = '|';

    private PlacementRecordCodec() {}

    /** Decode and structurally validate the canonical bytes; refuses with one reason per defect. */
    public static PlacementRecord decode(byte[] canonical) {
        if (canonical == null
                || canonical.length < FIXED_LENGTH + 1
                || canonical.length > FIXED_LENGTH + MAX_HOMESERVER_ID_LENGTH) {
            throw new PlacementRecordException(PlacementRecordRejection.WRONG_LENGTH);
        }
        if (!Arrays.equals(Arrays.copyOfRange(canonical, 0, MAGIC.length), MAGIC)) {
            throw new PlacementRecordException(PlacementRecordRejection.BAD_MAGIC);
        }
        int version = canonical[4] & 0xFF;
        if (version != VERSION) {
            throw new PlacementRecordException(PlacementRecordRejection.UNSUPPORTED_VERSION);
        }
        int generation = canonical[5] & 0xFF;
        if (generation != GENERATION) {
            throw new PlacementRecordException(PlacementRecordRejection.UNSUPPORTED_GENERATION);
        }

        byte[] accountIdRaw = Arrays.copyOfRange(canonical, 6, 6 + AccountId.RAW_LENGTH);
        if (accountIdRaw[0] != AccountId.FORMAT_VERSION) {
            throw new PlacementRecordException(PlacementRecordRejection.BAD_ACCOUNT_ID_VERSION);
        }
        byte rootClass = AccountId.rootClass(accountIdRaw);
        if (PlacementRecord.Origin.of(rootClass) == null) {
            throw new PlacementRecordException(PlacementRecordRejection.UNKNOWN_ACCOUNT_CLASS);
        }

        PlacementRecord.Origin origin = PlacementRecord.Origin.of(canonical[40]);
        if (origin == null) {
            throw new PlacementRecordException(PlacementRecordRejection.UNKNOWN_ORIGIN);
        }
        // The origin byte is redundant with the class byte on purpose: an id whose class says bootstrap and
        // whose record claims a genesis root is the audit marker ADM-008 decision 2 relies on, and a record
        // that disagrees with itself is refused rather than resolved in either direction.
        if (origin.code() != rootClass) {
            throw new PlacementRecordException(PlacementRecordRejection.ORIGIN_CLASS_MISMATCH);
        }

        int idLength = canonical[41] & 0xFF;
        if (idLength < 1 || idLength > MAX_HOMESERVER_ID_LENGTH) {
            throw new PlacementRecordException(PlacementRecordRejection.BAD_HOMESERVER_ID_LENGTH);
        }
        if (canonical.length != FIXED_LENGTH + idLength) {
            throw new PlacementRecordException(PlacementRecordRejection.DECLARED_LENGTH_MISMATCH);
        }
        String homeserverId = homeserverId(canonical, idLength);

        int offset = 42 + idLength;
        Instant issuedAt = instant(canonical, offset);
        Instant notBefore = instant(canonical, offset + 8);
        Instant notAfter = instant(canonical, offset + 16);
        if (!notAfter.isAfter(notBefore)) {
            throw new PlacementRecordException(PlacementRecordRejection.WINDOW_NOT_ORDERED);
        }

        return new PlacementRecord(version, generation, AccountId.encode(accountIdRaw), origin,
                homeserverId, issuedAt, notBefore, notAfter);
    }

    /**
     * The canonical bytes for a record. For tests and offline signing tools only: the resolver signs no
     * record and re-encodes none, because the bytes that were signed are the bytes it received.
     */
    public static byte[] encode(PlacementRecord record) {
        byte[] accountIdRaw = AccountId.decode(record.accountId());
        byte[] homeserverId = record.homeserverId().getBytes(StandardCharsets.US_ASCII);
        if (homeserverId.length < 1 || homeserverId.length > MAX_HOMESERVER_ID_LENGTH) {
            throw new PlacementRecordException(PlacementRecordRejection.BAD_HOMESERVER_ID_LENGTH);
        }
        byte[] out = new byte[FIXED_LENGTH + homeserverId.length];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        out[4] = (byte) record.version();
        out[5] = (byte) record.generation();
        System.arraycopy(accountIdRaw, 0, out, 6, accountIdRaw.length);
        out[40] = record.origin().code();
        out[41] = (byte) homeserverId.length;
        System.arraycopy(homeserverId, 0, out, 42, homeserverId.length);
        int offset = 42 + homeserverId.length;
        putLong(out, offset, record.issuedAt().toEpochMilli());
        putLong(out, offset + 8, record.notBefore().toEpochMilli());
        putLong(out, offset + 16, record.notAfter().toEpochMilli());
        return out;
    }

    private static String homeserverId(byte[] canonical, int idLength) {
        char[] chars = new char[idLength];
        for (int i = 0; i < idLength; i++) {
            int b = canonical[42 + i] & 0xFF;
            // Printable ASCII only, and never the delimiter the checkpoint leaves are built with, so one
            // leaf string can only be read one way.
            if (b <= 0x20 || b >= 0x7F || b == LEAF_DELIMITER) {
                throw new PlacementRecordException(PlacementRecordRejection.INVALID_HOMESERVER_ID);
            }
            chars[i] = (char) b;
        }
        return new String(chars);
    }

    private static Instant instant(byte[] bytes, int offset) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (bytes[offset + i] & 0xFFL);
        }
        // Epoch milliseconds are unsigned on the wire; anything that reads negative as a signed long is far
        // past any representable time and is refused rather than wrapped.
        if (value < 0) {
            throw new PlacementRecordException(PlacementRecordRejection.TIMESTAMP_OUT_OF_RANGE);
        }
        return Instant.ofEpochMilli(value);
    }

    private static void putLong(byte[] out, int offset, long value) {
        for (int i = 0; i < 8; i++) {
            out[offset + i] = (byte) (value >>> (8 * (7 - i)));
        }
    }
}
