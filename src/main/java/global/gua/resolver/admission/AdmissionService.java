package global.gua.resolver.admission;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.CanonicalMemberEntry;
import global.gua.resolver.roster.CanonicalRoster;
import global.gua.resolver.roster.MemberAttestation;
import global.gua.resolver.roster.MemberEntryJson;
import global.gua.resolver.roster.MemberEntryVerifier;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.RosterVerifier;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;
import global.gua.resolver.roster.store.RosterEntryRepository;

/**
 * The authority's admission control (§3, §5). Admitting a homeserver is the only way a roster entry comes
 * into being, and every admit/suspend/revoke is appended to the transparency log before the roster is
 * re-signed, so the membership history is tamper-evident and auditable. Admission enforces three gates:
 * proof of control over the registered signing key, a domain-ownership proof, and claim non-overlap.
 *
 * <p>An applicant proves possession either by signing its own roster entry (a member block, ADM-007) or, on
 * the legacy path, by signing its bare server name. The key it registers is retained as the anchor of its
 * attestation chain: from then on only that key, or a key it signs a rotation to, can change the entry's
 * address, issuer, key or search policy through {@link #attest}. The authority keeps weight, acceptsNew,
 * claims and status.
 */
@Service
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class AdmissionService {

    private static final Logger log = LoggerFactory.getLogger(AdmissionService.class);

    private final RosterEntryRepository entries;
    private final TransparencyLog transparencyLog;
    private final RosterStore rosterStore;
    private final DomainOwnershipVerifier domainVerifier;
    private final RosterVerifier rosterVerifier;
    private final ResolverProperties props;
    private final ObjectMapper json;

    public AdmissionService(RosterEntryRepository entries, TransparencyLog transparencyLog,
                            RosterStore rosterStore, DomainOwnershipVerifier domainVerifier,
                            RosterVerifier rosterVerifier, ResolverProperties props, ObjectMapper json) {
        this.entries = entries;
        this.transparencyLog = transparencyLog;
        this.rosterStore = rosterStore;
        this.domainVerifier = domainVerifier;
        this.rosterVerifier = rosterVerifier;
        this.props = props;
        this.json = json;
    }

    /** Vet and admit a new homeserver; appends ADMIT to the log and re-signs the roster. */
    @Transactional
    public SignedRoster admit(AdmissionRequest req) {
        boolean selfSigned = req.member() != null;

        // Gate 1 — proof the applicant controls the signing key it is registering (membership credential).
        if (!selfSigned) {
            if (props.getRoster().isRequireMemberSignature()) {
                throw new AdmissionException("a member self-signature is required: "
                        + "gua.resolver.roster.require-member-signature is on");
            }
            if (req.keyPossessionProof() == null || req.keyPossessionProof().isBlank()) {
                throw new AdmissionException("keyPossessionProof is required without a member block");
            }
            if (!Ed25519.verify(Ed25519.publicKey(req.signingKey()),
                    req.serverName().getBytes(StandardCharsets.UTF_8), req.keyPossessionProof())) {
                throw new AdmissionException("key-possession proof invalid for " + req.serverName());
            }
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

        Homeserver.SearchVisibility visibility = parseSearchVisibility(req);
        String id = admittedId(req, selfSigned);
        if (entries.findById(id).isPresent()) {
            throw new AdmissionException("federation id " + id + " is already admitted");
        }

        Homeserver hs = new Homeserver(id, req.serverName(), req.baseUrl(), req.masIssuer(),
                req.region(), Math.max(0, req.weight()), req.acceptsNew(), req.signingKey(),
                visibility, req.searchGroups() == null ? List.of() : req.searchGroups());
        Instant acceptedAt = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        String entryHash = null;
        if (selfSigned) {
            MemberEntryVerifier.Result result =
                    rosterVerifier.memberVerifier().verify(hs, req.member(), acceptedAt, null);
            if (!result.valid()) {
                throw new AdmissionException("member attestation rejected: " + result.reason());
            }
            requireNoUnexpectedSignatures(req.member(), false);
            entryHash = result.entryHash();
        } else {
            log.warn("Admitting {} without a member self-signature; the authority alone can still rewrite "
                    + "this entry until its operator attests it (ADM-007)", req.serverName());
        }

        RosterEntry entry = new RosterEntry(hs, req.claims(), acceptedAt, RosterEntry.Status.ACTIVE,
                req.member());
        entries.insert(entry, hs.signingKey(), selfSigned ? null : req.keyPossessionProof(), entryHash);
        appendLog("ADMIT", entry);
        if (selfSigned) {
            recordAttestation(entry, entryHash, acceptedAt);
        }
        log.info("Admitted homeserver {} ({}) with {} claim(s), member self-signature: {}",
                id, hs.serverName(), req.claims().size(), selfSigned);
        return rosterStore.refresh();
    }

    /**
     * Accept a member's attestation of its own entry: the member-controlled fields are replaced with the
     * signed values, a {@code MEMBER_ATTEST} leaf commits to the accepted bytes, and a history row keeps the
     * chain. This is how an already-admitted homeserver adopts a self-signed entry, updates its address, or
     * rotates its key, without a REVOKE and a new admission.
     */
    @Transactional
    public SignedRoster attest(String id, MemberAttestationRequest request) {
        if (request == null || request.homeserver() == null || request.member() == null) {
            throw new AdmissionException("homeserver and member blocks are both required");
        }
        RosterEntry stored = entries.findById(id)
                .orElseThrow(() -> new AdmissionException("no such homeserver: " + id));
        if (stored.status() == RosterEntry.Status.REVOKED) {
            throw new AdmissionException(id + " is revoked: a revoked member is admitted afresh, "
                    + "never re-attested");
        }
        String genesisKey = stored.homeserver().signingKey();
        if (genesisKey == null || genesisKey.isBlank()) {
            throw new AdmissionException(id + " has no registered key to anchor an attestation: "
                    + "revoke it and admit the operator afresh");
        }

        MemberAttestationRequest.HomeserverFields fields = request.homeserver();
        if (fields.id() != null && !fields.id().isBlank() && !fields.id().equals(id)) {
            throw new AdmissionException("path id " + id + " does not match the signed homeserver id "
                    + fields.id());
        }
        if (!stored.homeserver().serverName().equals(fields.serverName())) {
            throw new AdmissionException("serverName cannot change: a different server name is a new "
                    + "identity, which is a fresh admission");
        }
        requireText(fields.baseUrl(), "baseUrl");
        requireText(fields.masIssuer(), "masIssuer");
        requireText(fields.signingKey(), "signingKey");

        Homeserver.SearchVisibility visibility = fields.searchVisibility() == null
                ? Homeserver.SearchVisibility.GLOBAL
                : fields.searchVisibility();
        List<String> groups = fields.searchGroups() == null ? List.of() : fields.searchGroups();
        requireVisibilityAndGroupsAgree(visibility, groups);

        Homeserver attested = new Homeserver(id, stored.homeserver().serverName(), fields.baseUrl(),
                fields.masIssuer(), fields.region(), stored.homeserver().weight(),
                stored.homeserver().acceptsNew(), fields.signingKey(), visibility, groups);

        MemberEntryVerifier.Prior prior = priorOf(stored);
        if (request.member().sequence() <= prior.sequence()) {
            throw new AdmissionException("sequence must be greater than the accepted " + prior.sequence());
        }
        boolean rotation = !genesisKey.equals(fields.signingKey());
        Instant acceptedAt = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        MemberEntryVerifier.Result result =
                rosterVerifier.memberVerifier().verify(attested, request.member(), acceptedAt, prior);
        if (!result.valid()) {
            throw new AdmissionException("member attestation rejected: " + result.reason());
        }
        requireNoUnexpectedSignatures(request.member(), rotation);

        // Conditional on the entry still holding the sequence this attestation was verified against: the
        // read above and this write are not serialised against a concurrent attest, and the loser of that
        // race must not overwrite the winner with a lower sequence.
        int updated = entries.updateMember(id, attested, request.member(), result.entryHash(),
                prior.sequence());
        if (updated == 0) {
            throw new AdmissionException("a concurrent attestation changed " + id + " while this one was "
                    + "verified against sequence " + prior.sequence() + "; retry against the current entry");
        }
        RosterEntry accepted = new RosterEntry(attested, stored.claims(), stored.admittedAt(),
                stored.status(), request.member());
        recordAttestation(accepted, result.entryHash(), acceptedAt);
        log.info("Accepted member attestation for {} (sequence {}, keyId {}{})", id,
                request.member().sequence(), request.member().keyId(), rotation ? ", key rotation" : "");
        return rosterStore.refresh();
    }

    /**
     * Search discoverability is part of the signed roster, so it is validated at the admission gate:
     * GROUP visibility without any group would silently hide the homeserver from everyone, which is
     * almost certainly a misconfiguration, and groups on non-GROUP visibility would be dead config.
     */
    private static Homeserver.SearchVisibility parseSearchVisibility(AdmissionRequest req) {
        String raw = req.searchVisibility();
        Homeserver.SearchVisibility visibility;
        if (raw == null || raw.isBlank()) {
            visibility = Homeserver.SearchVisibility.GLOBAL;
        } else {
            try {
                visibility = Homeserver.SearchVisibility.valueOf(raw.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new AdmissionException("unknown searchVisibility: " + raw);
            }
        }
        requireVisibilityAndGroupsAgree(visibility,
                req.searchGroups() == null ? List.of() : req.searchGroups());
        return visibility;
    }

    private static void requireVisibilityAndGroupsAgree(Homeserver.SearchVisibility visibility,
                                                        List<String> groups) {
        boolean hasGroups = groups != null && !groups.isEmpty();
        if (visibility == Homeserver.SearchVisibility.GROUP && !hasGroups) {
            throw new AdmissionException("searchVisibility GROUP requires at least one search group");
        }
        if (visibility != Homeserver.SearchVisibility.GROUP && hasGroups) {
            throw new AdmissionException("searchGroups are only valid with searchVisibility GROUP");
        }
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

    /** Commit to the accepted entry: one MEMBER_ATTEST leaf, one history row, both at the acceptance time. */
    private void recordAttestation(RosterEntry entry, String entryHash, Instant acceptedAt) {
        SignedRoster.LogCheckpoint head = transparencyLog.append(TransparencyLog.MEMBER_ATTEST,
                entry.homeserver().id(), entryHash, acceptedAt);
        entries.insertMemberHistory(entry.homeserver().id(), entry.member(),
                entry.homeserver().signingKey(),
                MemberEntryJson.signedFields(json, entry.homeserver(), entry.member()), entryHash,
                acceptedAt, head.size() - 1);
    }

    /** What this authority accepted last for that homeserver: the chain the next entry has to continue. */
    private static MemberEntryVerifier.Prior priorOf(RosterEntry stored) {
        MemberAttestation member = stored.member();
        if (member == null) {
            return new MemberEntryVerifier.Prior(null, stored.homeserver().signingKey(), 0, null);
        }
        String hash;
        try {
            hash = CanonicalMemberEntry.hash(stored.homeserver(), member);
        } catch (RuntimeException e) {
            hash = null;   // a stored entry that no longer encodes cannot pin the next one by hash
        }
        return new MemberEntryVerifier.Prior(member.keyId(), stored.homeserver().signingKey(),
                member.sequence(), hash);
    }

    /**
     * Only the entry's own key signs it, plus the previous key on a rotation. Signatures sit outside the
     * canonical bytes, so anything else carried here is unsigned material the authority would be storing and
     * serving on the member's behalf.
     */
    private static void requireNoUnexpectedSignatures(MemberAttestation member, boolean rotation) {
        int allowed = rotation ? 2 : 1;
        if (member.signatures().size() > allowed) {
            throw new AdmissionException(rotation
                    ? "a rotation carries exactly the new key's and the previous key's signatures"
                    : "an entry carries exactly its own key's signature");
        }
    }

    private static String admittedId(AdmissionRequest req, boolean selfSigned) {
        if (selfSigned) {
            if (req.id() == null || req.id().isBlank()) {
                throw new AdmissionException("id is required with a member block: it is part of the "
                        + "signed entry");
            }
            return req.id();
        }
        return (req.id() == null || req.id().isBlank()) ? deriveId(req.serverName()) : req.id();
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new AdmissionException(field + " is required");
        }
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
