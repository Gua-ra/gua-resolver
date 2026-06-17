package global.gua.resolver.admission;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.CanonicalRoster;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;
import global.gua.resolver.roster.store.RosterEntryRepository;

/**
 * The authority's admission control (§3, §5). Admitting a homeserver is the only way a roster entry comes
 * into being, and every admit/suspend/revoke is appended to the transparency log before the roster is
 * re-signed — so the membership history is tamper-evident and auditable. Admission enforces three gates:
 * proof of control over the registered signing key, a domain-ownership proof, and claim non-overlap.
 */
@Service
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class AdmissionService {

    private static final Logger log = LoggerFactory.getLogger(AdmissionService.class);

    private final RosterEntryRepository entries;
    private final TransparencyLog transparencyLog;
    private final RosterStore rosterStore;
    private final DomainOwnershipVerifier domainVerifier;

    public AdmissionService(RosterEntryRepository entries, TransparencyLog transparencyLog,
                            RosterStore rosterStore, DomainOwnershipVerifier domainVerifier) {
        this.entries = entries;
        this.transparencyLog = transparencyLog;
        this.rosterStore = rosterStore;
        this.domainVerifier = domainVerifier;
    }

    /** Vet and admit a new homeserver; appends ADMIT to the log and re-signs the roster. */
    @Transactional
    public SignedRoster admit(AdmissionRequest req) {
        // Gate 1 — proof the applicant controls the signing key it is registering (membership credential).
        if (!Ed25519.verify(Ed25519.publicKey(req.signingKey()),
                req.serverName().getBytes(StandardCharsets.UTF_8), req.keyPossessionProof())) {
            throw new AdmissionException("key-possession proof invalid for " + req.serverName());
        }
        // Gate 2 — domain ownership.
        if (!domainVerifier.verify(req.serverName(), req.domainProof())) {
            throw new AdmissionException("domain-ownership proof rejected for " + req.serverName());
        }
        // Gate 3 — uniqueness + claim non-overlap against currently-admitted entries.
        if (entries.existsByServerName(req.serverName())) {
            throw new AdmissionException(req.serverName() + " is already admitted");
        }
        List<RosterEntry> existing = entries.findAll().stream().filter(RosterEntry::isActive).toList();
        for (RosterEntry e : existing) {
            if (ClaimOverlap.conflicts(req.claims(), e.claims())) {
                throw new AdmissionException(
                        "requested claims overlap those of " + e.homeserver().serverName());
            }
        }

        String id = (req.id() == null || req.id().isBlank()) ? deriveId(req.serverName()) : req.id();
        Homeserver hs = new Homeserver(id, req.serverName(), req.baseUrl(), req.masIssuer(),
                req.region(), Math.max(0, req.weight()), req.acceptsNew(), req.signingKey());
        RosterEntry entry = new RosterEntry(hs, req.claims(), Instant.now(), RosterEntry.Status.ACTIVE);

        entries.insert(entry);
        appendLog("ADMIT", entry);
        log.info("Admitted homeserver {} ({}) with {} claim(s)", id, hs.serverName(), req.claims().size());
        return rosterStore.refresh();
    }

    /** Suspend (temporarily) or revoke (permanently) an admitted homeserver; logged + re-signed. */
    @Transactional
    public SignedRoster setStatus(String id, RosterEntry.Status status) {
        RosterEntry entry = entries.findById(id)
                .orElseThrow(() -> new AdmissionException("no such homeserver: " + id));
        entries.updateStatus(id, status);
        transparencyLog.append(status.name(), id, MerkleTree.sha256Hex(id + ":" + status));
        log.info("Set homeserver {} status -> {}", id, status);
        return rosterStore.refresh();
    }

    private void appendLog(String type, RosterEntry entry) {
        byte[] canonical = CanonicalRoster.bytes(0, 0, new SignedRoster.LogCheckpoint("", 0), List.of(entry));
        transparencyLog.append(type, entry.homeserver().id(),
                MerkleTree.sha256Hex(new String(canonical, StandardCharsets.UTF_8)));
    }

    private static String deriveId(String serverName) {
        return serverName.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-");
    }

    public static class AdmissionException extends RuntimeException {
        public AdmissionException(String message) {
            super(message);
        }
    }
}
