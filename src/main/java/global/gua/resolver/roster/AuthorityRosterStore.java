package global.gua.resolver.roster;

import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.store.RosterEntryRepository;

/**
 * Authority-mode {@link RosterStore} (§5): the roster's source of truth. Builds the published roster from
 * the persisted admitted entries, anchors it to the current transparency-log checkpoint, and threshold-
 * signs it. On a fresh database it seeds the single configured dev homeserver (Phase 1) and logs an ADMIT
 * event, so the audit trail exists from the very first entry.
 *
 * <p>The roster {@code version} tracks the transparency-log size — every membership change appends a log
 * event, so a stable log size means a stable roster, and the signed snapshot is cached + only rebuilt when
 * the log advances (or {@link #refresh()} is called).
 */
@Component
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class AuthorityRosterStore implements RosterStore {

    private static final Logger log = LoggerFactory.getLogger(AuthorityRosterStore.class);

    private final RosterEntryRepository entries;
    private final TransparencyLog transparencyLog;
    private final RosterSigner signer;
    private final RosterVerifier verifier;
    private final ResolverProperties props;

    private volatile SignedRoster cached;
    private volatile long cachedLogSize = -1;

    public AuthorityRosterStore(RosterEntryRepository entries, TransparencyLog transparencyLog,
                                RosterSigner signer, RosterVerifier verifier, ResolverProperties props) {
        this.entries = entries;
        this.transparencyLog = transparencyLog;
        this.signer = signer;
        this.verifier = verifier;
        this.props = props;
        seedIfEmpty();
    }

    @Override
    public SignedRoster current() {
        SignedRoster.LogCheckpoint head = transparencyLog.head();
        SignedRoster snapshot = cached;
        if (snapshot == null || cachedLogSize != head.size()) {
            snapshot = rebuild(head);
        }
        return snapshot;
    }

    @Override
    public synchronized SignedRoster refresh() {
        return rebuild(transparencyLog.head());
    }

    private synchronized SignedRoster rebuild(SignedRoster.LogCheckpoint head) {
        List<RosterEntry> all = entries.findAll();
        long version = head.size();
        SignedRoster signed = signer.sign(version, Instant.now(), all, head);
        if (!verifier.isVerified(signed)) {
            // Authority is misconfigured (no/short of signing keys for the threshold). Don't serve an
            // unverifiable roster silently — clients/mirrors would reject it anyway.
            log.error("Authority produced a roster below the {}-of-n signature threshold; "
                    + "check gua.resolver.authority.signing-private-key / trusted-keys / threshold",
                    verifier.threshold());
        }
        cached = signed;
        cachedLogSize = head.size();
        return signed;
    }

    /** Seed the configured dev homeserver into a fresh roster (Phase 1) and record the ADMIT event. */
    private void seedIfEmpty() {
        if (entries.count() > 0) {
            return;
        }
        ResolverProperties.DevHomeserver d = props.getDevHomeserver();
        Homeserver hs = new Homeserver(d.getId(), d.getServerName(), d.getBaseUrl(), d.getMasIssuer(),
                d.getRegion(), 1, true, d.getSigningKey() == null ? "" : d.getSigningKey());
        RosterEntry entry = new RosterEntry(hs, List.of(), Instant.now(), RosterEntry.Status.ACTIVE);
        entries.insert(entry);
        transparencyLog.append("ADMIT", hs.id(),
                global.gua.resolver.crypto.MerkleTree.sha256Hex(
                        new String(CanonicalRoster.bytes(0, 0,
                                new SignedRoster.LogCheckpoint("", 0), List.of(entry)))));
        log.info("Seeded roster with dev homeserver '{}' ({})", hs.id(), hs.serverName());
    }
}
