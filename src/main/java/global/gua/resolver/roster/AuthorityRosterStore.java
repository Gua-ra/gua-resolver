package global.gua.resolver.roster;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.store.RosterEntryRepository;

/** The roster version is the transparency-log size. An under-signed roster is logged and still served. */
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
    private volatile Instant cachedValidUntil;
    private volatile long unattestedActive;
    private volatile Set<String> reportedUnattested;

    public AuthorityRosterStore(RosterEntryRepository entries, TransparencyLog transparencyLog,
                                RosterSigner signer, RosterVerifier verifier, ResolverProperties props) {
        this.entries = entries;
        this.transparencyLog = transparencyLog;
        this.signer = signer;
        this.verifier = verifier;
        this.props = props;
        seedIfEmpty();
        refresh();
    }

    @Override
    public SignedRoster current() {
        SignedRoster.LogCheckpoint head = transparencyLog.head();
        SignedRoster snapshot = cached;
        if (snapshot == null || cachedLogSize != head.size() || attestationWindowPassed()) {
            snapshot = rebuild(head);
        }
        return snapshot;
    }

    @Override
    public synchronized SignedRoster refresh() {
        return rebuild(transparencyLog.head());
    }

    @Override
    public long unattestedActiveCount() {
        current();
        return unattestedActive;
    }

    private boolean attestationWindowPassed() {
        Instant until = cachedValidUntil;
        return until != null && !Instant.now().isBefore(until);
    }

    private synchronized SignedRoster rebuild(SignedRoster.LogCheckpoint head) {
        Instant now = Instant.now();
        // PENDING entries stay out of the signed bytes: older mirrors and clients cannot parse the status.
        List<RosterEntry> admitted = entries.findAll().stream().filter(e -> !e.isPending()).toList();
        RosterVerifier.VerifiedView view = verifier.verifiedView(admitted, now, id -> null, Set.of());
        report(view);

        long version = head.size();
        SignedRoster signed = signer.sign(version, now, view.entries(), head);
        if (!verifier.isVerified(signed)) {
            log.error("Authority produced a roster below the {}-of-n signature threshold; "
                    + "check gua.resolver.authority.signing-private-key / trusted-keys / threshold",
                    verifier.threshold());
        }
        cached = signed;
        cachedLogSize = head.size();
        cachedValidUntil = view.nextWindowChange();
        unattestedActive = view.unattestedActiveCount();
        return signed;
    }

    private void report(RosterVerifier.VerifiedView view) {
        Set<String> unattested = view.unattestedActiveIds();
        if (unattested.equals(reportedUnattested)) {
            return;
        }
        reportedUnattested = unattested;
        if (unattested.isEmpty()) {
            log.info("Every ACTIVE roster entry carries a valid member self-signature");
            return;
        }
        if (verifier.requireMemberSignature()) {
            for (RosterVerifier.MemberCheck check : view.excluded()) {
                log.error("Excluding ACTIVE homeserver {} from the signed roster: {}",
                        check.homeserverId(), check.result().reason());
            }
            return;
        }
        log.warn("{} ACTIVE homeserver(s) have no valid member self-signature and are served anyway: {}. "
                        + "Attest them before setting gua.resolver.roster.require-member-signature "
                        + "(docs/runbooks/member-attestation.md)",
                unattested.size(), String.join(", ", unattested));
    }

    private void seedIfEmpty() {
        if (entries.count() > 0) {
            return;
        }
        ResolverProperties.DevHomeserver d = props.getDevHomeserver();
        Homeserver hs = new Homeserver(d.getId(), d.getServerName(), d.getBaseUrl(), d.getMasIssuer(),
                d.getRegion(), 1, true, d.getSigningKey() == null ? "" : d.getSigningKey());
        RosterEntry.Status seeded = props.getGovernance().isRequired()
                ? RosterEntry.Status.PENDING
                : RosterEntry.Status.ACTIVE;
        RosterEntry entry = new RosterEntry(hs, List.of(), Instant.now(), seeded);
        entries.insert(entry);
        transparencyLog.append("ADMIT", hs.id(),
                global.gua.resolver.crypto.MerkleTree.sha256Hex(
                        new String(CanonicalRoster.bytes(0, 0,
                                new SignedRoster.LogCheckpoint("", 0), List.of(entry)))));
        log.info("Seeded roster with dev homeserver '{}' ({})", hs.id(), hs.serverName());
    }
}
