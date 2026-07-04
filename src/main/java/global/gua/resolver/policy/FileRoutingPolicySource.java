package global.gua.resolver.policy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.roster.RosterStore;

/** File-backed policy source. On refresh failure it keeps serving the last verified bundle, if any. */
@Component
@ConditionalOnProperty(name = "gua.resolver.policy.enabled", havingValue = "true")
public class FileRoutingPolicySource implements RoutingPolicySource {

    private static final Logger log = LoggerFactory.getLogger(FileRoutingPolicySource.class);

    private final Path file;
    private final ObjectMapper json;
    private final RosterStore rosterStore;
    private final RoutingPolicyValidator validator;
    private final RoutingPolicyVerifier verifier;

    private volatile RoutingPolicyBundle current;
    private volatile Instant loadedAt;
    private volatile String lastMessage = "not loaded";

    public FileRoutingPolicySource(ResolverProperties props, ObjectMapper json, RosterStore rosterStore,
                                   RoutingPolicyValidator validator, RoutingPolicyVerifier verifier) {
        String configured = props.getPolicy().getFile();
        if (configured == null || configured.isBlank()) {
            throw new IllegalStateException("gua.resolver.policy.file is required when policy.enabled=true");
        }
        this.file = Path.of(configured);
        this.json = json;
        this.rosterStore = rosterStore;
        this.validator = validator;
        this.verifier = verifier;
        refresh();
    }

    @Override
    public Optional<RoutingPolicyBundle> current() {
        return Optional.ofNullable(current);
    }

    @Override
    public PolicySourceStatus status() {
        RoutingPolicyBundle bundle = current;
        return new PolicySourceStatus("file:" + file, bundle != null,
                bundle == null ? null : bundle.version(), loadedAt, lastMessage);
    }

    @Scheduled(fixedDelayString = "${gua.resolver.policy.refresh-interval:PT1M}")
    public synchronized void refresh() {
        try {
            RoutingPolicyBundle loaded = json.readValue(Files.readString(file), RoutingPolicyBundle.class);
            validator.validate(loaded, rosterStore.current());
            verifier.requireVerified(loaded);
            current = loaded;
            loadedAt = Instant.now();
            lastMessage = "loaded";
            log.info("Loaded routing policy {} v{} from {}", loaded.policyId(), loaded.version(), file);
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
