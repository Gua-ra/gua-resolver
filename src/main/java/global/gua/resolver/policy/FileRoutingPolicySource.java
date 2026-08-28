package global.gua.resolver.policy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.roster.RosterStore;

/**
 * File-backed policy source. On refresh failure it keeps serving the last verified bundle, if any, but never
 * serves a bundle that is outside its own signed validity window (an expired/not-yet-active policy degrades
 * to no policy, so placement falls back deterministically rather than applying stale governance data), and
 * never accepts a lower version than the one already loaded (rollback protection).
 */
@Component
@ConditionalOnProperty(name = "gua.resolver.policy.enabled", havingValue = "true")
public class FileRoutingPolicySource implements RoutingPolicySource {

    private static final Logger log = LoggerFactory.getLogger(FileRoutingPolicySource.class);

    private final Path file;
    private final ObjectMapper json;
    private final RosterStore rosterStore;
    private final RoutingPolicyValidator validator;
    private final RoutingPolicyVerifier verifier;
    private final List<PolicyPublicationListener> publicationListeners;
    private final Clock clock;

    private volatile RoutingPolicyBundle current;
    private volatile Instant loadedAt;
    private volatile String lastMessage = "not loaded";

    @Autowired
    public FileRoutingPolicySource(ResolverProperties props, ObjectMapper json, RosterStore rosterStore,
                                   RoutingPolicyValidator validator, RoutingPolicyVerifier verifier,
                                   List<PolicyPublicationListener> publicationListeners) {
        this(props, json, rosterStore, validator, verifier, publicationListeners, Clock.systemUTC());
    }

    FileRoutingPolicySource(ResolverProperties props, ObjectMapper json, RosterStore rosterStore,
                            RoutingPolicyValidator validator, RoutingPolicyVerifier verifier,
                            List<PolicyPublicationListener> publicationListeners, Clock clock) {
        String configured = props.getPolicy().getFile();
        if (configured == null || configured.isBlank()) {
            throw new IllegalStateException("gua.resolver.policy.file is required when policy.enabled=true");
        }
        this.file = Path.of(configured);
        this.json = json;
        this.rosterStore = rosterStore;
        this.validator = validator;
        this.verifier = verifier;
        this.publicationListeners = publicationListeners == null ? List.of() : publicationListeners;
        this.clock = clock;
        refresh();
    }

    @Override
    public Optional<RoutingPolicyBundle> current() {
        RoutingPolicyBundle bundle = current;
        if (bundle == null || !withinValidityWindow(bundle)) {
            return Optional.empty();
        }
        return Optional.of(bundle);
    }

    @Override
    public PolicySourceStatus status() {
        RoutingPolicyBundle bundle = current;
        boolean healthy = bundle != null && withinValidityWindow(bundle);
        String message = bundle != null && !withinValidityWindow(bundle) ? "loaded but outside validity window"
                : lastMessage;
        return new PolicySourceStatus("file:" + file, healthy,
                bundle == null ? null : bundle.version(), loadedAt, message);
    }

    private boolean withinValidityWindow(RoutingPolicyBundle bundle) {
        Instant now = Instant.now(clock);
        if (bundle.notBefore() != null && bundle.notBefore().isAfter(now)) {
            return false;
        }
        return bundle.expiresAt() == null || bundle.expiresAt().isAfter(now);
    }

    @Scheduled(fixedDelayString = "${gua.resolver.policy.refresh-interval:PT1M}")
    public synchronized void refresh() {
        try {
            RoutingPolicyBundle loaded = json.readValue(Files.readString(file), RoutingPolicyBundle.class);
            validator.validate(loaded, rosterStore.current());
            verifier.requireVerified(loaded);
            // Rollback protection is only meaningful against a policy we are actually still serving. If the
            // current bundle has expired (withinValidityWindow=false), it no longer floors the version, so an
            // operator can recover by re-adopting a signed, in-window lower/equal version instead of being
            // deadlocked until a brand-new higher version is minted.
            RoutingPolicyBundle existing = current;
            if (existing != null && withinValidityWindow(existing) && loaded.version() < existing.version()) {
                throw new IllegalStateException("routing policy rollback rejected: loaded v" + loaded.version()
                        + " < current v" + existing.version());
            }
            boolean newVersion = existing == null || loaded.version() != existing.version()
                    || !loaded.policyId().equals(existing.policyId());
            current = loaded;
            loadedAt = Instant.now(clock);
            lastMessage = "loaded";
            log.info("Loaded routing policy {} v{} from {}", loaded.policyId(), loaded.version(), file);
            if (newVersion) {
                for (PolicyPublicationListener listener : publicationListeners) {
                    listener.onPolicyAdopted(loaded);
                }
            }
        } catch (Exception e) {
            lastMessage = e.getMessage();
            if (current == null) {
                throw new IllegalStateException("no valid routing policy loaded from " + file, e);
            }
            log.warn("Keeping last valid routing policy because {} failed validation/load: {}",
                    file, e.getMessage());
        }
    }
}
