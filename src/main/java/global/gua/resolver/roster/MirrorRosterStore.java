package global.gua.resolver.roster;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.MerkleTree;

/**
 * Mirror-mode {@link RosterStore} (§4): pulls the signed roster from an upstream authority, verifies the
 * k-of-n authority signatures AND transparency-log consistency before serving it, then refreshes
 * periodically. An institution runs this to get a local, low-latency, sovereign copy of the roster
 * WITHOUT being an authority — it can never mint roster entries, only relay verified ones.
 *
 * <p>The directory (phone graph) is deliberately NOT mirrored here — it is queried, rate-limited, against
 * the authoritative store; only the public roster is replicated.
 */
@Component
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "MIRROR")
public class MirrorRosterStore implements RosterStore {

    private static final Logger log = LoggerFactory.getLogger(MirrorRosterStore.class);

    private final WebClient upstream;
    private final RosterVerifier verifier;
    private final ObjectMapper json;
    private final Path cacheFile;

    private volatile SignedRoster verified;
    private volatile SignedRoster.LogCheckpoint lastCheckpoint;

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
    @Scheduled(fixedDelayString = "${gua.resolver.mirror.refresh-interval:PT5M}")
    public synchronized SignedRoster refresh() {
        SignedRoster pulled = upstream.get().uri("/roster")
                .retrieve().bodyToMono(SignedRoster.class).block();
        if (pulled == null) {
            throw new IllegalStateException("upstream returned no roster");
        }

        // 1. Threshold signatures must verify against the published authority key set.
        verifier.requireVerified(pulled);

        // 2. Transparency-log consistency: the new checkpoint must be an append-only extension of the last
        //    one we accepted (gossip check — detects a forked/rewritten history / split view).
        if (lastCheckpoint != null && lastCheckpoint.size() > 0) {
            requireConsistentLog(lastCheckpoint, pulled.logCheckpoint());
        }

        this.verified = pulled;
        this.lastCheckpoint = pulled.logCheckpoint();
        saveCachedRoster(pulled);
        log.info("Mirror refreshed: roster v{} ({} entries), log size {}",
                pulled.version(), pulled.entries().size(), pulled.logCheckpoint().size());
        return pulled;
    }

    private boolean loadCachedRoster() {
        if (cacheFile == null || !Files.isRegularFile(cacheFile)) {
            return false;
        }
        try {
            SignedRoster cached = json.readValue(Files.readString(cacheFile), SignedRoster.class);
            verifier.requireVerified(cached);
            this.verified = cached;
            this.lastCheckpoint = cached.logCheckpoint();
            log.info("Loaded cached verified roster v{} from {}", cached.version(), cacheFile);
            return true;
        } catch (Exception e) {
            log.warn("Could not load cached roster from {}: {}", cacheFile, e.getMessage());
            return false;
        }
    }

    private void saveCachedRoster(SignedRoster roster) {
        if (cacheFile == null) {
            return;
        }
        try {
            Path parent = cacheFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(cacheFile, json.writeValueAsString(roster));
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
