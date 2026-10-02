package global.gua.resolver.api;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.policy.CompositeRoutingPolicyProvider;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicySource;

/** Public signed routing-policy distribution and status surface for mirrors, clients, and auditors. */
@RestController
public class PolicyController {

    private final CompositeRoutingPolicyProvider policies;

    public PolicyController(CompositeRoutingPolicyProvider policies) {
        this.policies = policies;
    }

    @GetMapping("/policy/routing")
    public RoutingPolicyBundle routingPolicy() {
        return policies.current().orElseThrow(() -> new NoPolicyException("no routing policy configured"));
    }

    @GetMapping("/policy/routing/status")
    public List<RoutingPolicySource.PolicySourceStatus> routingPolicyStatus() {
        return policies.statuses();
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    static class NoPolicyException extends RuntimeException {
        NoPolicyException(String message) {
            super(message);
        }
    }
}
