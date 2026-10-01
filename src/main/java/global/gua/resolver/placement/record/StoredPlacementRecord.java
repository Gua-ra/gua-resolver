/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

public record StoredPlacementRecord(
        String accountId,
        String homeserverId,
        int generation,
        PlacementRecord.Origin origin,
        Instant issuedAt,
        Instant notBefore,
        Instant notAfter,
        String recordB64,
        String signatureB64,
        Instant receivedAt) {

    public PlacementRecordEnvelope envelope() {
        return new PlacementRecordEnvelope(recordB64, signatureB64);
    }

    public byte[] recordBytes() {
        return decode(Base64.getUrlDecoder(), recordB64);
    }

    public byte[] signatureBytes() {
        return decode(Base64.getDecoder(), signatureB64);
    }

    /** Compared as decoded bytes: one signature can arrive in several base64 spellings. */
    public boolean sameSignedBytesAs(StoredPlacementRecord other) {
        byte[] mine = recordBytes();
        byte[] theirs = other.recordBytes();
        byte[] mySignature = signatureBytes();
        byte[] theirSignature = other.signatureBytes();
        if (mine == null || theirs == null || mySignature == null || theirSignature == null) {
            // Unreachable: nothing undecodable is stored.
            return recordB64.equals(other.recordB64) && signatureB64.equals(other.signatureB64);
        }
        return Arrays.equals(mine, theirs) && Arrays.equals(mySignature, theirSignature);
    }

    public static StoredPlacementRecord of(PlacementRecordVerifier.Verified verified, Instant receivedAt) {
        PlacementRecord record = verified.record();
        return new StoredPlacementRecord(record.accountId(), record.homeserverId(), record.generation(),
                record.origin(), record.issuedAt(), record.notBefore(), record.notAfter(),
                verified.envelope().record(), verified.envelope().signature(), receivedAt);
    }

    private static byte[] decode(Base64.Decoder decoder, String value) {
        try {
            return value == null ? null : decoder.decode(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
