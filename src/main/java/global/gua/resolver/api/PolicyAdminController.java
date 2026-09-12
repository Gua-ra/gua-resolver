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
import org.springframework.web.server.ResponseStatusException;

import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicySigner;
import global.gua.resolver.policy.RoutingPolicyValidator;
import global.gua.resolver.policy.RoutingPolicyVerifier;
import global.gua.resolver.roster.RosterStore;

/**
 * Authority admin surface for routing-policy governance. Signing happens HERE, next to the roster the
 * bundle is validated against, so the authority private key never leaves the service boundary — authoring
 * tooling submits an unsigned (but delegate-signed) bundle and receives the authority-signed result.
 * Under {@code /authority/**}: ADMIN via HTTP Basic, fails closed when no admin hash is configured.
 */
@RestController
@RequestMapping("/authority")
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class PolicyAdminController {

    private static final Logger log = LoggerFactory.getLogger(PolicyAdminController.class);

    private final RoutingPolicyValidator validator;
    private final RoutingPolicySigner signer;
    private final RoutingPolicyVerifier verifier;
    private final RosterStore rosterStore;

    public PolicyAdminController(RoutingPolicyValidator validator, RoutingPolicySigner signer,
                                 RoutingPolicyVerifier verifier, RosterStore rosterStore) {
        this.validator = validator;
        this.signer = signer;
        this.verifier = verifier;
        this.rosterStore = rosterStore;
    }

    /**
     * Validate a policy bundle against the CURRENT signed roster (every target must be an active member)
     * and return it with this authority's signature applied. Delegate signatures must be produced by the
     * delegates themselves beforehand; {@code delegateVerifiedZones} in the response tells the operator
     * which zones will actually route once the bundle is served.
     */
    @PostMapping("/policy/sign")
    public SignedPolicyResponse sign(@RequestBody RoutingPolicyBundle unsigned) {
        if (!signer.canSign()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "this node has no policy signing key configured");
        }
        validator.validate(unsigned, rosterStore.current());
        RoutingPolicyBundle signed = signer.sign(unsigned);
        Set<String> delegateVerified = verifier.delegateVerifiedZones(signed);
        log.info("Authority-signed routing policy {} v{} ({} zones, {} delegate-verified)",
                signed.policyId(), signed.version(),
                signed.delegationZones() == null ? 0 : signed.delegationZones().size(),
                delegateVerified.size());
        return new SignedPolicyResponse(signed, delegateVerified);
    }

    @ExceptionHandler(RoutingPolicyValidator.RoutingPolicyValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ProblemResponse onInvalidPolicy(RoutingPolicyValidator.RoutingPolicyValidationException e) {
        return new ProblemResponse("policy_invalid", e.getMessage());
    }

    public record SignedPolicyResponse(RoutingPolicyBundle policy, Set<String> delegateVerifiedZones) {}

    public record ProblemResponse(String code, String message) {}
}
