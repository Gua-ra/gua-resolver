/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Re-verifies every stored record against the current roster after the roster changes, and counts the ones
 * whose signer is no longer ACTIVE.
 *
 * <p>A placement record is verified at acceptance time against the roster as it was then. Membership moves:
 * a homeserver is suspended, revoked, or loses its member attestation, and the records it signed are then
 * held by this node with no active signer behind them. Nothing routes on them, so this is not an outage, but
 * it is the number the Phase 4 exit criteria require to be zero, so it has to be measured rather than
 * assumed.
 *
 * <p>It only measures. A record is never rewritten, re-signed or deleted here: custody means the bytes that
 * arrived are the bytes that stay, and retraction is explicitly undefined in this phase.
 */
@Component
@ConditionalOnExpression(PlacementFeature.ENABLED)
public class PlacementRecordAuditor {

    private static final Logger log = LoggerFactory.getLogger(PlacementRecordAuditor.class);

    private static final int PAGE = 500;

    private final JdbcPlacementRecordStore store;
    private final RosterStore rosterStore;

    private final AtomicLong orphanedByRoster = new AtomicLong();
    private final AtomicLong invalidSignature = new AtomicLong();
    private final AtomicLong auditedRosterVersion = new AtomicLong(-1);

    public PlacementRecordAuditor(JdbcPlacementRecordStore store, RosterStore rosterStore,
                                  MeterRegistry metrics) {
        this.store = store;
        this.rosterStore = rosterStore;
        metrics.gauge("gua.resolver.placement.orphaned.by.roster", orphanedByRoster, AtomicLong::get);
        metrics.gauge("gua.resolver.placement.reverify.failures", invalidSignature, AtomicLong::get);
        metrics.gauge("gua.resolver.placement.audited.roster.version", auditedRosterVersion,
                AtomicLong::get);
    }

    /** What one sweep found. */
    public record AuditResult(long rosterVersion, long records, long orphanedByRoster,
                              long invalidSignature) {}

    /** Sweep when the roster has moved since the last sweep; the common case is to do nothing. */
    @Scheduled(fixedDelayString = "${gua.resolver.placement.audit-interval:PT5M}")
    public synchronized void auditIfRosterChanged() {
        long version = rosterStore.current().version();
        if (version == auditedRosterVersion.get()) {
            return;
        }
        audit();
    }

    /** Re-verify every stored record against the roster as it is now. */
    public synchronized AuditResult audit() {
        SignedRoster roster = rosterStore.current();
        Map<String, PublicKey> activeKeys = activeKeys(roster);

        long records = 0;
        long orphaned = 0;
        long invalid = 0;
        String cursor = null;
        List<StoredPlacementRecord> page;
        while (!(page = store.page(cursor, PAGE)).isEmpty()) {
            for (StoredPlacementRecord record : page) {
                records++;
                PublicKey key = activeKeys.get(record.homeserverId());
                if (key == null) {
                    orphaned++;
                    continue;
                }
                if (!verifies(record, key)) {
                    invalid++;
                }
            }
            cursor = page.get(page.size() - 1).accountId();
        }

        orphanedByRoster.set(orphaned);
        invalidSignature.set(invalid);
        auditedRosterVersion.set(roster.version());
        if (orphaned > 0 || invalid > 0) {
            log.warn("Placement audit at roster version {}: {} record(s), {} with no ACTIVE signer, "
                    + "{} whose signature no longer verifies", roster.version(), records, orphaned, invalid);
        } else {
            log.info("Placement audit at roster version {}: {} record(s), all verify under an ACTIVE "
                    + "roster key", roster.version(), records);
        }
        return new AuditResult(roster.version(), records, orphaned, invalid);
    }

    private static Map<String, PublicKey> activeKeys(SignedRoster roster) {
        Map<String, PublicKey> keys = new HashMap<>();
        for (RosterEntry entry : roster.activeEntries()) {
            try {
                keys.put(entry.homeserver().id(), Ed25519.publicKey(entry.homeserver().signingKey()));
            } catch (IllegalArgumentException e) {
                // An entry whose key cannot be read cannot verify anything; its records count as orphaned.
                log.warn("ACTIVE roster entry {} has no usable Ed25519 signing key", entry.homeserver().id());
            }
        }
        return keys;
    }

    private static boolean verifies(StoredPlacementRecord record, PublicKey key) {
        try {
            byte[] canonical = Base64.getUrlDecoder().decode(record.recordB64());
            return Ed25519.verify(key, canonical, record.signatureB64());
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
