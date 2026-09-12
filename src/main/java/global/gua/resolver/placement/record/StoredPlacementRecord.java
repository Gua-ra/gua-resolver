package global.gua.resolver.placement.record;

import java.time.Instant;

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

    /** The row a verified record becomes. */
    public static StoredPlacementRecord of(PlacementRecordVerifier.Verified verified, Instant receivedAt) {
        PlacementRecord record = verified.record();
        return new StoredPlacementRecord(record.accountId(), record.homeserverId(), record.generation(),
                record.origin(), record.issuedAt(), record.notBefore(), record.notAfter(),
                verified.envelope().record(), verified.envelope().signature(), receivedAt);
    }
}
