package global.gua.resolver.policy;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Component;

/** Chooses the highest-version verified policy among all configured sources. */
@Component
public class CompositeRoutingPolicyProvider {

    private final List<RoutingPolicySource> sources;

    public CompositeRoutingPolicyProvider(List<RoutingPolicySource> sources) {
        this.sources = List.copyOf(sources);
    }

    public Optional<RoutingPolicyBundle> current() {
        return sources.stream()
                .map(RoutingPolicySource::current)
                .flatMap(Optional::stream)
                .max(Comparator.comparingLong(RoutingPolicyBundle::version)
                        .thenComparing(RoutingPolicyBundle::policyId));
    }

    public List<RoutingPolicySource.PolicySourceStatus> statuses() {
        return sources.stream().map(RoutingPolicySource::status).toList();
    }
}
