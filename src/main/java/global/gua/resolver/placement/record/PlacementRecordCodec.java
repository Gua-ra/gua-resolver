/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;

/** Strict big-endian fixed-layout codec. Malformed input is refused, never repaired. */
public final class PlacementRecordCodec {

    /** ASCII "GUAP", also the signature domain separating a record from anything else a roster key signs. */
    public static final byte[] MAGIC = {'G', 'U', 'A', 'P'};

    public static final int VERSION = 0x01;
    public static final int GENERATION = 0x01;

    public static final int FIXED_LENGTH = 66;

    public static final int MAX_HOMESERVER_ID_LENGTH = 64;

    /** The checkpoint leaf delimiter, refused inside a homeserver id. */
    private static final char LEAF_DELIMITER = '|';

    private PlacementRecordCodec() {}

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

    /** For tests and offline signing only: ingest never re-encodes. */
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
        // Epoch milliseconds are unsigned on the wire; a value that reads negative is refused.
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
