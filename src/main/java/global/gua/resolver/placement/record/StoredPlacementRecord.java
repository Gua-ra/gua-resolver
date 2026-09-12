/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

/**
 * One row of {@code placement_record}: the decoded fields the resolver indexes on, plus the received bytes
 * and signature held verbatim.
 *
 * <p>The verbatim pair is the authoritative copy. Reads serve it unchanged and the auditor re-verifies from
 * it, so nothing a consumer checks depends on this node having decoded the record the same way twice.
 */
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

    /** The signed envelope exactly as it arrived. */
    public PlacementRecordEnvelope envelope() {
        return new PlacementRecordEnvelope(recordB64, signatureB64);
    }

    /** The canonical bytes this row holds, decoded from the spelling they were received in. */
    public byte[] recordBytes() {
        return decode(Base64.getUrlDecoder(), recordB64);
    }

    /** The detached signature this row holds, decoded from the spelling it was received in. */
    public byte[] signatureBytes() {
        return decode(Base64.getDecoder(), signatureB64);
    }

    /**
     * Whether two rows carry the same signed object, compared as bytes rather than as transport spellings.
     *
     * <p>This is what makes a retry idempotent for a well-behaved signer. The record field has one canonical
     * spelling and the verifier refuses every other, but the detached signature is plain base64, whose
     * padding a decoder treats as optional, so one signature can still arrive spelled two ways. Comparing
     * the strings would read that as a re-issue and refuse the retry as stale, which is the opposite of the
     * rule ADM-008 decision 7 states: the same homeserver re-presenting the same record changes nothing.
     */
    public boolean sameSignedBytesAs(StoredPlacementRecord other) {
        byte[] mine = recordBytes();
        byte[] theirs = other.recordBytes();
        byte[] mySignature = signatureBytes();
        byte[] theirSignature = other.signatureBytes();
        if (mine == null || theirs == null || mySignature == null || theirSignature == null) {
            // Nothing undecodable reaches storage, so this is unreachable; still, fall back to the spelling
            // rather than call two rows the same object on the strength of a decode that failed.
            return recordB64.equals(other.recordB64) && signatureB64.equals(other.signatureB64);
        }
        return Arrays.equals(mine, theirs) && Arrays.equals(mySignature, theirSignature);
    }

    /** The row a verified record becomes. */
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
