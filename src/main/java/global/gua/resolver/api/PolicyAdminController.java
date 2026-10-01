package global.gua.resolver.api;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicyValidator;
import global.gua.resolver.policy.RoutingPolicyVerifier;
import global.gua.resolver.roster.RosterStore;

@RestController
@RequestMapping("/authority")
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class PolicyAdminController {

    private static final Logger log = LoggerFactory.getLogger(PolicyAdminController.class);

    private final RoutingPolicyValidator validator;
    private final RoutingPolicyVerifier verifier;
    private final RosterStore rosterStore;

    public PolicyAdminController(RoutingPolicyValidator validator, RoutingPolicyVerifier verifier,
                                 RosterStore rosterStore) {
        this.validator = validator;
        this.verifier = verifier;
        this.rosterStore = rosterStore;
    }

    @PostMapping("/policy/validate")
    public ValidatedPolicyResponse validate(@RequestBody RoutingPolicyBundle bundle) {
        validator.validate(bundle, rosterStore.current());
        Set<String> delegateVerified = verifier.delegateVerifiedZones(bundle);
        boolean signaturesVerified = verifier.isVerified(bundle);
        log.info("Validated routing policy {} v{} ({} zones, {} delegate-verified, governance signatures {})",
                bundle.policyId(), bundle.version(),
                bundle.delegationZones() == null ? 0 : bundle.delegationZones().size(),
                delegateVerified.size(), signaturesVerified ? "verify" : "do NOT verify");
        return new ValidatedPolicyResponse(true, signaturesVerified, delegateVerified);
    }

    @ExceptionHandler(RoutingPolicyValidator.RoutingPolicyValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ProblemResponse onInvalidPolicy(RoutingPolicyValidator.RoutingPolicyValidationException e) {
        return new ProblemResponse("policy_invalid", e.getMessage());
    }

    public record ValidatedPolicyResponse(boolean structureValid, boolean signaturesVerified,
                                          Set<String> delegateVerifiedZones) {}

    public record ProblemResponse(String code, String message) {}
}
