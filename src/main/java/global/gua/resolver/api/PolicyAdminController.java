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

/**
 * Authority admin surface for routing-policy governance: validation only.
 *
 * <p>This endpoint used to sign. Signing a policy bundle is a governance act, and ADM-001 L8 requires the
 * key roles to stop sharing, so the signing key left this process in Phase 2: an operator signs a bundle
 * offline with the governance key and ships the signed file. What is left here is the part that genuinely
 * needs the live roster, and cannot be done offline: checking that every target is an active member, that
 * each rule sits inside its delegation zone, and that the delegate signatures present will actually route.
 *
 * <p>Validating here and signing elsewhere means an operator can still see, before publishing, exactly what
 * the resolver will make of a bundle. {@code signaturesVerified} answers the question that matters most
 * after the cutover: whether the bundle verifies under the governance keys this resolver trusts, so a bundle
 * still signed by the retired operational key is caught before it is deployed rather than at startup.
 */
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

    /**
     * Validate a bundle against the current signed roster and report what the resolver would do with it.
     * Nothing is signed and nothing is adopted.
     */
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

    /**
     * @param structureValid      the bundle passed structural and federation-boundary validation
     * @param signaturesVerified  it carries enough valid signatures under this resolver's policy trust root,
     *                            which is the governance key set once a genesis is loaded
     * @param delegateVerifiedZones the zones whose rules will actually route
     */
    public record ValidatedPolicyResponse(boolean structureValid, boolean signaturesVerified,
                                          Set<String> delegateVerifiedZones) {}

    public record ProblemResponse(String code, String message) {}
}
