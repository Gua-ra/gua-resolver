package global.gua.resolver.roster;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.MerkleTree;

/**
 * Mirror-mode {@link RosterStore} (§4): pulls the signed roster from an upstream authority, verifies the
 * k-of-n authority signatures AND transparency-log consistency before serving it, then refreshes
 * periodically. An institution runs this to get a local, low-latency, sovereign copy of the roster
 * WITHOUT being an authority: it can never mint roster entries, only relay verified ones.
 *
 * <p>It serves the upstream document verbatim at {@code GET /roster} ({@link #served()}), so a client can
 * still check the upstream signature over exactly those bytes, and routes on its own verified view of it
 * ({@link #current()}): each entry's member self-signature is checked against the last entry this mirror
 * accepted for that homeserver, which is what catches an authority that substitutes a member's address or
 * key, or replays an older entry (ADM-007). Under
 * {@code gua.resolver.roster.require-member-signature} an ACTIVE entry that fails is dropped from that view.
 *
 * <p>The directory is deliberately NOT mirrored here; a mirror queries the AUTHORITY-mode node's
 * directory (whose member write endpoint is removed, ADM-001 L1b) row by row; only the public roster is
 * replicated.
 */
@Component
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "MIRROR")
public class MirrorRosterStore implements RosterStore {

    private static final Logger log = LoggerFactory.getLogger(MirrorRosterStore.class);

    private final WebClient upstream;
    private final RosterVerifier verifier;
    private final ObjectMapper json;
    private final Path cacheFile;
    private final Map<String, MemberEntryVerifier.Prior> priors = new ConcurrentHashMap<>();

    private volatile SignedRoster served;
    private volatile SignedRoster verified;
    private volatile SignedRoster.LogCheckpoint lastCheckpoint;
    private volatile long unattestedActive;

    public MirrorRosterStore(ResolverProperties props, RosterVerifier verifier, WebClient.Builder builder,
                             ObjectMapper json) {
        this.verifier = verifier;
        this.json = json;
        String base = props.getMirror().getUpstreamUrl();
        if (base == null || base.isBlank()) {
            throw new IllegalStateException("gua.resolver.mirror.upstream-url is required in MIRROR mode");
        }
        String configuredCache = props.getMirror().getCacheFile();
        this.cacheFile = (configuredCache == null || configuredCache.isBlank())
                ? null
                : Path.of(configuredCache);
        this.upstream = builder.baseUrl(base).build();
        try {
            refresh();
        } catch (RuntimeException e) {
            if (!loadCachedRoster()) {
                throw e;
            }
            log.warn("Mirror started from cached verified roster because upstream refresh failed: {}",
                    e.getMessage());
        }
    }

    @Override
    public SignedRoster current() {
        SignedRoster r = verified;
        if (r == null) {
            throw new IllegalStateException("mirror has no verified roster yet");
        }
        return r;
    }

    @Override
    public SignedRoster served() {
        SignedRoster r = served;
        if (r == null) {
            throw new IllegalStateException("mirror has no verified roster yet");
        }
        return r;
    }

    @Override
    public long unattestedActiveCount() {
        return unattestedActive;
    }

    @Override
    @Scheduled(fixedDelayString = "${gua.resolver.mirror.refresh-interval:PT5M}")
    public synchronized SignedRoster refresh() {
        String document = upstream.get().uri("/roster").retrieve().bodyToMono(String.class).block();
        if (document == null || document.isBlank()) {
            throw new IllegalStateException("upstream returned no roster");
        }
        SignedRoster pulled = parse(document);

        // 1. Threshold signatures must verify against the published authority key set.
        verifier.requireVerified(pulled);

        // 2. Transparency-log consistency: the new checkpoint must be an append-only extension of the last
        //    one this mirror accepted. A local check against our own last checkpoint, not gossip: it detects
        //    a history rewritten since we last looked, not a split view between readers (ADM-001 L12).
        if (lastCheckpoint != null && lastCheckpoint.size() > 0) {
            requireConsistentLog(lastCheckpoint, pulled.logCheckpoint());
        }

        // 3. Per-entry member self-signatures, against what this mirror accepted before.
        SignedRoster view = accept(pulled, MemberEntryJson.malformedMemberEntries(json, tree(document)));
        this.lastCheckpoint = pulled.logCheckpoint();
        saveCachedRoster(document);
        log.info("Mirror refreshed: roster v{} ({} entries, {} routable), log size {}",
                pulled.version(), pulled.entries().size(), view.entries().size(),
                pulled.logCheckpoint().size());
        return view;
    }

    private SignedRoster parse(String document) {
        try {
            return json.treeToValue(tree(document), SignedRoster.class);
        } catch (Exception e) {
            throw new RosterVerifier.RosterVerificationException("upstream roster does not parse: "
                    + e.getMessage());
        }
    }

    private JsonNode tree(String document) {
        return MemberEntryJson.readTree(json, document);
    }

    /**
     * Record the verified view and advance this mirror's per-homeserver state. Only an entry that verified
     * becomes the prior for the next refresh, so a refused entry can never move the sequence forward or
     * install a key the previous key did not sign.
     */
    private SignedRoster accept(SignedRoster pulled, Set<String> malformed) {
        Instant now = Instant.now();
        RosterVerifier.VerifiedView view =
                verifier.verifiedView(pulled.entries(), now, priors::get, malformed);
        Map<String, RosterEntry> byId = new HashMap<>();
        pulled.entries().forEach(e -> byId.put(e.homeserver().id(), e));

        for (RosterVerifier.MemberCheck check : view.checks()) {
            RosterEntry entry = byId.get(check.homeserverId());
            if (check.result().valid() && entry != null && entry.member() != null) {
                priors.put(check.homeserverId(), new MemberEntryVerifier.Prior(entry.member().keyId(),
                        entry.homeserver().signingKey(), entry.member().sequence(),
                        check.result().entryHash()));
            } else if (check.result().outcome() == MemberEntryVerifier.Outcome.INVALID) {
                log.error("Upstream roster entry {} failed member verification: {}{}",
                        check.homeserverId(), check.result().reason(),
                        verifier.requireMemberSignature() && check.active() ? " (dropped)" : " (tolerated)");
            }
        }

        SignedRoster verifiedView = new SignedRoster(pulled.version(), pulled.issuedAt(), view.entries(),
                pulled.logCheckpoint(), pulled.authoritySignatures());
        this.served = pulled;
        this.verified = verifiedView;
        this.unattestedActive = view.unattestedActiveCount();
        return verifiedView;
    }

    private boolean loadCachedRoster() {
        if (cacheFile == null || !Files.isRegularFile(cacheFile)) {
            return false;
        }
        try {
            String document = Files.readString(cacheFile);
            SignedRoster cached = parse(document);
            verifier.requireVerified(cached);
            accept(cached, MemberEntryJson.malformedMemberEntries(json, tree(document)));
            this.lastCheckpoint = cached.logCheckpoint();
            log.info("Loaded cached verified roster v{} from {}", cached.version(), cacheFile);
            return true;
        } catch (Exception e) {
            log.warn("Could not load cached roster from {}: {}", cacheFile, e.getMessage());
            return false;
        }
    }

    /** Cache the upstream document verbatim: it is the artifact whose signature covers exactly those bytes. */
    private void saveCachedRoster(String document) {
        if (cacheFile == null) {
            return;
        }
        try {
            Path parent = cacheFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(cacheFile, document);
        } catch (Exception e) {
            log.warn("Could not persist verified roster cache to {}: {}", cacheFile, e.getMessage());
        }
    }

    private void requireConsistentLog(SignedRoster.LogCheckpoint older, SignedRoster.LogCheckpoint newer) {
        if (newer.size() < older.size()) {
            throw new RosterVerifier.RosterVerificationException(
                    "upstream log shrank (" + older.size() + " -> " + newer.size() + "): possible rollback");
        }
        if (newer.size() == older.size()) {
            if (!newer.merkleRoot().equals(older.merkleRoot())) {
                throw new RosterVerifier.RosterVerificationException("log root changed without growth: split view");
            }
            return;
        }
        ConsistencyResponse cr = upstream.get()
                .uri(b -> b.path("/roster/log/consistency")
                        .queryParam("first", older.size())
                        .queryParam("second", newer.size()).build())
                .retrieve().bodyToMono(ConsistencyResponse.class).block();
        List<String> proof = cr == null ? List.of() : cr.proof();
        boolean ok = MerkleTree.verifyConsistency((int) older.size(), (int) newer.size(),
                older.merkleRoot(), newer.merkleRoot(), proof);
        if (!ok) {
            throw new RosterVerifier.RosterVerificationException(
                    "transparency-log consistency proof failed (" + older.size() + " -> " + newer.size() + ")");
        }
    }

    public record ConsistencyResponse(int first, int second, List<String> proof) {}
}
