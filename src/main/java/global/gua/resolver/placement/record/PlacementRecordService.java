/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.roster.MemberEntryJson;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/** Not transactional: each write is a single statement whose WHERE clause carries its condition. */
@Service
@ConditionalOnExpression(PlacementFeature.ENABLED)
public class PlacementRecordService {

    private static final Logger log = LoggerFactory.getLogger(PlacementRecordService.class);

    public enum Outcome { STORED, REPLACED, UNCHANGED }

    private final PlacementRecordVerifier verifier;
    private final JdbcPlacementRecordStore store;
    private final ObjectMapper json;
    private final MeterRegistry metrics;
    private final Counter conflicts;

    public PlacementRecordService(PlacementRecordVerifier verifier, JdbcPlacementRecordStore store,
                                  ObjectMapper json, MeterRegistry metrics) {
        this.verifier = verifier;
        this.store = store;
        this.json = json;
        this.metrics = metrics;
        this.conflicts = Counter.builder("gua.resolver.placement.conflicts").register(metrics);
    }

    public Outcome ingest(byte[] body, Instant now) {
        try {
            PlacementRecordEnvelope envelope;
            try {
                envelope = MemberEntryJson.read(json, body, PlacementRecordEnvelope.class);
            } catch (MemberEntryJson.MalformedMemberEntryException e) {
                throw new PlacementRecordException(PlacementRecordRejection.MALFORMED_ENVELOPE);
            }
            PlacementRecordVerifier.Verified verified = verifier.verify(envelope, now);
            Outcome outcome = store(verified, now);
            metrics.counter("gua.resolver.placement.records.accepted",
                    "result", outcome.name().toLowerCase(Locale.ROOT)).increment();
            return outcome;
        } catch (PlacementRecordException e) {
            metrics.counter("gua.resolver.placement.record.rejections",
                    "reason", e.reason()).increment();
            throw e;
        }
    }

    public void requireIngestEnabled(boolean enabled) {
        if (!enabled) {
            PlacementRecordException e =
                    new PlacementRecordException(PlacementRecordRejection.INGEST_DISABLED);
            metrics.counter("gua.resolver.placement.record.rejections", "reason", e.reason()).increment();
            throw e;
        }
    }

    public Optional<StoredPlacementRecord> find(String accountId) {
        return store.find(accountId);
    }

    public List<StoredPlacementRecord> listByHomeserver(String homeserverId, String cursor, int limit) {
        return store.listByHomeserver(homeserverId, cursor, limit);
    }

    private Outcome store(PlacementRecordVerifier.Verified verified, Instant now) {
        StoredPlacementRecord incoming = StoredPlacementRecord.of(verified, now);
        Optional<StoredPlacementRecord> existing = store.find(incoming.accountId());
        if (existing.isEmpty()) {
            try {
                store.insert(incoming);
                return Outcome.STORED;
            } catch (DuplicateKeyException e) {
                // Another ingest won the race for this accountId; decide against what it wrote.
                StoredPlacementRecord raced = store.find(incoming.accountId())
                        .orElseThrow(() -> new PlacementRecordException(
                                PlacementRecordRejection.PLACEMENT_CONFLICT));
                return reconcile(raced, incoming);
            }
        }
        return reconcile(existing.get(), incoming);
    }

    private Outcome reconcile(StoredPlacementRecord held, StoredPlacementRecord incoming) {
        if (!held.homeserverId().equals(incoming.homeserverId())) {
            // accountIds are not identifiers, so the pair is safe to log.
            log.error("Placement conflict for accountId={}: held by homeserverId={}, claimed by "
                            + "homeserverId={}; keeping the held record",
                    held.accountId(), held.homeserverId(), incoming.homeserverId());
            conflicts.increment();
            throw new PlacementRecordException(PlacementRecordRejection.PLACEMENT_CONFLICT);
        }
        if (held.sameSignedBytesAs(incoming)) {
            return Outcome.UNCHANGED;
        }
        if (!incoming.issuedAt().isAfter(held.issuedAt())) {
            throw new PlacementRecordException(PlacementRecordRejection.STALE_REISSUE);
        }
        if (store.replaceIfNewer(incoming) == 0) {
            // A concurrent re-issue already stored something at least as new; the newer record stands.
            return Outcome.UNCHANGED;
        }
        return Outcome.REPLACED;
    }
}
