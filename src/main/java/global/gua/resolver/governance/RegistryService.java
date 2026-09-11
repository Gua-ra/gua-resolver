package global.gua.resolver.governance;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.governance.store.RegistryEpochRepository;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;
import global.gua.resolver.roster.store.RosterEntryRepository;

/**
 * The HomeserverRegistry epoch path: it builds the membership the governance keys are asked to sign, accepts
 * a signed epoch, applies it, and commits it to the transparency log (ADM-001 L10).
 *
 * <p><b>An epoch ratifies, it does not originate.</b> The resolver rebuilds the pending membership from its
 * own state and refuses an epoch whose content hash is anything else. So governance cannot invent a status
 * the resolver never proposed, and the operational key cannot change a status without governance signing the
 * result. What each side can do alone is: the operational key proposes, governance ratifies or refuses. That
 * is the separation Phase 2 buys, and it is worth naming precisely, because it is narrower than "governance
 * controls membership".
 *
 * <p>With one operator holding both the operational key and the governance key, this separates processes and
 * custody, not principals (ADM-001 standing rule). It becomes a real control when a second operator holds a
 * governance key.
 */
@Service
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class RegistryService {

    private static final Logger log = LoggerFactory.getLogger(RegistryService.class);

    private final RosterEntryRepository entries;
    private final RegistryEpochRepository epochs;
    private final TransparencyLog transparencyLog;
    private final RosterStore rosterStore;
    private final GenesisLoader genesis;
    private final ObjectMapper json;

    public RegistryService(RosterEntryRepository entries, RegistryEpochRepository epochs,
                           TransparencyLog transparencyLog, RosterStore rosterStore, GenesisLoader genesis,
                           ObjectMapper json) {
        this.entries = entries;
        this.epochs = epochs;
        this.transparencyLog = transparencyLog;
        this.rosterStore = rosterStore;
        this.genesis = genesis;
        this.json = json;
    }

    /** The unsigned epoch an operator signs offline: what the resolver expects the next epoch to say. */
    public record PendingEpoch(String genesisId, Registry registry, long epoch, String previousEpochHash,
                               String contentHash, HomeserverRegistryContent content) {}

    /** An accepted epoch as served: the signed object, its hash, and the content it commits to. */
    public record PublishedEpoch(RegistryEpoch epoch, String epochHash, HomeserverRegistryContent content,
                                 Instant acceptedAt, Long logLeafIndex) {}

    /**
     * Build the membership the next epoch would carry. An entry admitted under governance is proposed
     * ACTIVE; an entry with a recorded status intent is proposed at that status; everything else keeps the
     * status it has, so an epoch is always a complete statement of membership rather than a delta.
     */
    public PendingEpoch pending() {
        GovernanceKeySet keys = genesis.requireKeySet();
        List<RegistryMember> members = new ArrayList<>();
        for (RosterEntryRepository.GovernanceRow row : entries.governanceRows()) {
            members.add(new RegistryMember(row.homeserverId(), proposedStatus(row), row.memberEntryHash(),
                    row.weight(), row.acceptsNew(), row.claims()));
        }
        HomeserverRegistryContent content = HomeserverRegistryContent.of(members);
        Optional<RegistryEpochRepository.StoredEpoch> current = epochs.findCurrent(Registry.HOMESERVERS);
        return new PendingEpoch(
                keys.genesisId(),
                Registry.HOMESERVERS,
                current.map(e -> e.epoch() + 1).orElse(1L),
                current.map(RegistryEpochRepository.StoredEpoch::epochHash).orElse(""),
                CanonicalHomeserverRegistryContent.hash(content),
                content);
    }

    private static RosterEntry.Status proposedStatus(RosterEntryRepository.GovernanceRow row) {
        if (row.pendingStatus() != null) {
            return row.pendingStatus();
        }
        return row.status() == RosterEntry.Status.PENDING ? RosterEntry.Status.ACTIVE : row.status();
    }

    public Optional<PublishedEpoch> current(Registry registry) {
        return epochs.findCurrent(registry).map(this::published);
    }

    public Optional<PublishedEpoch> at(Registry registry, long epoch) {
        return epochs.find(registry, epoch).map(this::published);
    }

    /**
     * Verify a governance-signed epoch and apply it. Every check is a refusal, never a repair: an epoch that
     * does not continue the chain, does not match the membership the resolver built, or does not carry
     * enough distinct operators' signatures changes nothing.
     */
    @Transactional
    public SignedRoster commit(RegistryEpoch submitted, HomeserverRegistryContent content) {
        GovernanceKeySet keys = genesis.requireKeySet();
        if (submitted == null || content == null) {
            throw new GovernanceException("an epoch and its content are both required");
        }
        submitted.validateShape();
        content.validateShape();
        if (submitted.registry() != Registry.HOMESERVERS) {
            throw new GovernanceException("only " + Registry.HOMESERVERS.wireName()
                    + " has an epoch path in Phase 2; " + submitted.registry().wireName()
                    + " content must stay empty until its phase lands");
        }
        if (!keys.genesisId().equals(submitted.genesisId())) {
            throw new GovernanceException("epoch names genesis " + submitted.genesisId()
                    + ", but this resolver is pinned to " + keys.genesisId());
        }

        String contentHash = CanonicalHomeserverRegistryContent.hash(content);
        if (!contentHash.equals(submitted.contentHash())) {
            throw new GovernanceException("the epoch's contentHash does not match the content sent with it");
        }

        // The resolver rebuilds the membership itself and refuses anything else: a signature over a hash
        // the resolver cannot reproduce from its own state is a signature over something it cannot mean.
        PendingEpoch expected = pending();
        if (submitted.epoch() != expected.epoch()) {
            throw new GovernanceException("expected epoch " + expected.epoch() + ", found "
                    + submitted.epoch());
        }
        if (!expected.previousEpochHash().equals(submitted.previousEpochHash())) {
            throw new GovernanceException("epoch " + submitted.epoch()
                    + " does not continue the chain: previousEpochHash does not match the accepted epoch");
        }
        if (!expected.contentHash().equals(contentHash)) {
            throw new GovernanceException("the signed membership is not the membership this resolver built; "
                    + "fetch the pending content again and sign that");
        }

        GovernanceVerifier.require(keys, CanonicalRegistryEpoch.bytes(submitted), submitted.signatures(),
                Registry.HOMESERVERS.wireName() + " epoch " + submitted.epoch());

        String epochHash = CanonicalRegistryEpoch.hash(submitted);
        Instant acceptedAt = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        for (RegistryMember member : content.members()) {
            int updated = entries.applyGovernedStatus(member.homeserverId(), member.status(),
                    (int) member.weight(), member.acceptsNew(), member.claims(), submitted.epoch());
            if (updated == 0) {
                throw new GovernanceException("epoch names homeserver " + member.homeserverId()
                        + ", which is not in the roster");
            }
        }

        SignedRoster.LogCheckpoint head = transparencyLog.append(TransparencyLog.MEMBERSHIP_EPOCH,
                null, epochHash, acceptedAt);
        epochs.insert(new RegistryEpochRepository.StoredEpoch(submitted.registry(), submitted.epoch(),
                submitted.genesisId(), submitted.previousEpochHash(), epochHash, submitted.issuedAt(),
                write(content), write(submitted.signatures()), acceptedAt, head.size() - 1));

        log.info("Accepted {} epoch {} ({} member(s), signed by {} operator(s)); membership now follows the "
                        + "governance keys", submitted.registry().wireName(), submitted.epoch(),
                content.members().size(),
                GovernanceVerifier.count(keys, CanonicalRegistryEpoch.bytes(submitted),
                        submitted.signatures()).operators());
        return rosterStore.refresh();
    }

    private PublishedEpoch published(RegistryEpochRepository.StoredEpoch stored) {
        List<GovernanceSignature> signatures = read(stored.signaturesJson());
        RegistryEpoch epoch = new RegistryEpoch(RegistryEpoch.SCHEMA, stored.registry(), stored.genesisId(),
                stored.epoch(), stored.previousHash(), stored.issuedAt(), contentHashOf(stored), signatures);
        return new PublishedEpoch(epoch, stored.epochHash(), content(stored), stored.acceptedAt(),
                stored.logLeafIndex());
    }

    private String contentHashOf(RegistryEpochRepository.StoredEpoch stored) {
        return CanonicalHomeserverRegistryContent.hash(content(stored));
    }

    private HomeserverRegistryContent content(RegistryEpochRepository.StoredEpoch stored) {
        return GovernanceJson.read(json, stored.contentJson(), HomeserverRegistryContent.class);
    }

    private List<GovernanceSignature> read(String signaturesJson) {
        try {
            return json.readValue(signaturesJson,
                    new com.fasterxml.jackson.core.type.TypeReference<List<GovernanceSignature>>() {});
        } catch (Exception e) {
            throw new IllegalStateException("corrupt registry_epoch.signatures_json", e);
        }
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException("cannot serialise a registry epoch", e);
        }
    }
}
