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
import global.gua.resolver.governance.GenesisLoader;
import global.gua.resolver.placement.rules.WeightedFallbackRule;
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
    private final GenesisLoader genesis;
    private final ObjectMapper json;

    public AdmissionService(RosterEntryRepository entries, TransparencyLog transparencyLog,
                            RosterStore rosterStore, DomainOwnershipVerifier domainVerifier,
                            RosterVerifier rosterVerifier, ResolverProperties props, GenesisLoader genesis,
                            ObjectMapper json) {
        this.entries = entries;
        this.transparencyLog = transparencyLog;
        this.rosterStore = rosterStore;
        this.domainVerifier = domainVerifier;
        this.rosterVerifier = rosterVerifier;
        this.props = props;
        this.genesis = genesis;
        this.json = json;
    }

    @Transactional
    public SignedRoster admit(AdmissionRequest req) {
        boolean selfSigned = req.member() != null;
        requireUsableKey(req.signingKey());

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
        if (!domainVerifier.verify(req.serverName(), req.domainProof())) {
            throw new AdmissionException("domain-ownership proof rejected for " + req.serverName());
        }
        if (entries.existsByServerName(req.serverName())) {
            throw new AdmissionException(req.serverName() + " is already admitted");
        }
        List<RosterEntry> unrevokedEntries = entries.findAll().stream()
                .filter(e -> e.status() != RosterEntry.Status.REVOKED).toList();
        for (RosterEntry e : unrevokedEntries) {
            if (ClaimOverlap.conflicts(req.claims(), e.claims())) {
                throw new AdmissionException(
                        "requested claims overlap those of " + e.homeserver().serverName());
            }
        }
        long addedWeight = req.acceptsNew() ? Math.max(0, req.weight()) : 0;
        long weightAfter = addedWeight + WeightedFallbackRule.totalWeight(unrevokedEntries.stream()
                .map(RosterEntry::homeserver).filter(Homeserver::acceptsNew).toList());
        if (addedWeight > 0 && weightAfter > WeightedFallbackRule.MAX_TOTAL_WEIGHT) {
            throw new AdmissionException(overWeightLimit(weightAfter));
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
            log.warn("Admitting homeserver {} without a member self-signature", req.serverName());
        }

        RosterEntry.Status initial = genesis.governanceRequired()
                ? RosterEntry.Status.PENDING
                : RosterEntry.Status.ACTIVE;
        RosterEntry entry = new RosterEntry(hs, req.claims(), acceptedAt, initial, req.member());
        entries.insert(entry, hs.signingKey(), selfSigned ? null : req.keyPossessionProof(), entryHash);
        appendLog("ADMIT", entry);
        if (selfSigned) {
            recordAttestation(entry, entryHash, acceptedAt);
        }
        log.info("Admitted homeserver {} ({}) with {} claim(s), member self-signature: {}, status: {}",
                id, hs.serverName(), req.claims().size(), selfSigned, initial);
        if (initial == RosterEntry.Status.PENDING) {
            log.info("Homeserver {} admission requires governance approval", id);
        }
        return rosterStore.refresh();
    }

    @Transactional
    public SignedRoster attest(String id, MemberAttestationRequest request) {
        if (request == null || request.homeserver() == null || request.member() == null) {
            throw new AdmissionException("homeserver and member blocks are both required");
        }
        RosterEntry stored = entries.findById(id)
                .orElseThrow(() -> new AdmissionException("no such homeserver: " + id));
        if (stored.status() == RosterEntry.Status.REVOKED) {
            throw new AdmissionException(id + " is revoked; submit a new admission");
        }
        String genesisKey = stored.homeserver().signingKey();
        if (genesisKey == null || genesisKey.isBlank()) {
            throw new AdmissionException(id + " has no registered signing key; revoke the entry and "
                    + "submit a new admission");
        }

        MemberAttestationRequest.HomeserverFields fields = request.homeserver();
        if (fields.id() != null && !fields.id().isBlank() && !fields.id().equals(id)) {
            throw new AdmissionException("path id " + id + " does not match the signed homeserver id "
                    + fields.id());
        }
        if (!stored.homeserver().serverName().equals(fields.serverName())) {
            throw new AdmissionException("serverName cannot change; submit a new admission for a "
                    + "different serverName");
        }
        requireText(fields.baseUrl(), "baseUrl");
        requireText(fields.masIssuer(), "masIssuer");
        requireText(fields.signingKey(), "signingKey");
        requireUsableKey(fields.signingKey());

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

        int updated = entries.updateMemberIfSequenceMatches(id, attested, request.member(), result.entryHash(),
                prior.sequence());
        if (updated == 0) {
            throw new AdmissionException("stored sequence for " + id + " changed after verification "
                    + "against sequence " + prior.sequence() + "; retry against the current entry");
        }
        RosterEntry accepted = new RosterEntry(attested, stored.claims(), stored.admittedAt(),
                stored.status(), request.member());
        recordAttestation(accepted, result.entryHash(), acceptedAt);
        log.info("Accepted member attestation for {} (sequence {}, keyId {}{})", id,
                request.member().sequence(), request.member().keyId(), rotation ? ", key rotation" : "");
        return rosterStore.refresh();
    }

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

    @Transactional
    public SignedRoster setStatus(String id, RosterEntry.Status status) {
        RosterEntry entry = entries.findById(id).orElseThrow(() -> new AdmissionException("no such homeserver: " + id));
        if (status == RosterEntry.Status.PENDING) {
            throw new AdmissionException("PENDING cannot be set directly");
        }
        if (status == RosterEntry.Status.ACTIVE && entry.status() != RosterEntry.Status.ACTIVE
                && entry.homeserver().acceptsNew()) {
            long weightAfter = Math.max(0, entry.homeserver().weight()) + WeightedFallbackRule.totalWeight(
                    entries.findAll().stream().filter(e -> e.status() == RosterEntry.Status.ACTIVE)
                            .map(RosterEntry::homeserver).filter(Homeserver::acceptsNew).toList());
            if (entry.homeserver().weight() > 0 && weightAfter > WeightedFallbackRule.MAX_TOTAL_WEIGHT) {
                throw new AdmissionException(overWeightLimit(weightAfter));
            }
        }
        if (genesis.governanceRequired()) {
            entries.setPendingStatus(id, status);
            transparencyLog.append(TransparencyLog.STATUS_INTENT, id,
                    MerkleTree.sha256Hex(id + ":" + status + ":intent"));
            log.info("Requested homeserver {} status {}; governance approval required", id, status);
            return rosterStore.current();
        }
        entries.updateStatus(id, status);
        transparencyLog.append(status.name(), id, MerkleTree.sha256Hex(id + ":" + status));
        log.info("Set homeserver {} status -> {}", id, status);
        return rosterStore.refresh();
    }

    private void recordAttestation(RosterEntry entry, String entryHash, Instant acceptedAt) {
        SignedRoster.LogCheckpoint head = transparencyLog.append(TransparencyLog.MEMBER_ATTEST,
                entry.homeserver().id(), entryHash, acceptedAt);
        entries.insertMemberHistory(entry.homeserver().id(), entry.member(),
                entry.homeserver().signingKey(),
                MemberEntryJson.signedFields(json, entry.homeserver(), entry.member()), entryHash,
                acceptedAt, head.size() - 1);
    }

    private static MemberEntryVerifier.Prior priorOf(RosterEntry stored) {
        MemberAttestation member = stored.member();
        if (member == null) {
            return new MemberEntryVerifier.Prior(null, stored.homeserver().signingKey(), 0, null);
        }
        String hash;
        try {
            hash = CanonicalMemberEntry.hash(stored.homeserver(), member);
        } catch (RuntimeException e) {
            hash = null;
        }
        return new MemberEntryVerifier.Prior(member.keyId(), stored.homeserver().signingKey(),
                member.sequence(), hash);
    }

    private static void requireNoUnexpectedSignatures(MemberAttestation member, boolean rotation) {
        int allowed = rotation ? 2 : 1;
        if (member.signatures().size() > allowed) {
            throw new AdmissionException(rotation
                    ? "key rotation requires exactly the new and previous keys' signatures"
                    : "a member entry requires exactly one signature from its signing key");
        }
    }

    private static String admittedId(AdmissionRequest req, boolean selfSigned) {
        if (selfSigned) {
            if (req.id() == null || req.id().isBlank()) {
                throw new AdmissionException("id is required with a member block");
            }
            return req.id();
        }
        return (req.id() == null || req.id().isBlank()) ? deriveId(req.serverName()) : req.id();
    }

    private static void requireUsableKey(String signingKey) {
        try {
            Ed25519.publicKey(signingKey);
        } catch (IllegalArgumentException e) {
            throw new AdmissionException("signingKey is not an acceptable Ed25519 public key");
        }
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new AdmissionException(field + " is required");
        }
    }

    private static String overWeightLimit(long weightAfter) {
        return "the homeservers that accept new accounts would weigh " + weightAfter
                + " in total, above the weighted fallback's limit of " + WeightedFallbackRule.MAX_TOTAL_WEIGHT;
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
