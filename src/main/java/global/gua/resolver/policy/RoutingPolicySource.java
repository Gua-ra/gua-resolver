package global.gua.resolver.policy;

import java.time.Instant;
import java.util.Optional;

/** A source that can distribute a verified routing-policy bundle. */
public interface RoutingPolicySource {

    Optional<RoutingPolicyBundle> current();

    PolicySourceStatus status();

    record PolicySourceStatus(String sourceId, boolean available, Long version, Instant loadedAt, String message) {}
}
