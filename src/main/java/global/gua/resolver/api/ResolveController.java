package global.gua.resolver.api;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonInclude;

import global.gua.resolver.claims.RoutingClaimsEnvelope;
import global.gua.resolver.claims.RoutingClaimsVerifier;
import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.directory.DirectoryUnavailableException;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.NoPlacementAvailableException;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.service.ResolutionService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * The federation front door the iOS and Android clients call before OIDC login. The client sends a phone
 * number and learns which homeserver to authenticate against; for a phone with no account it learns where to
 * register.
 *
 * <p>Nothing about the phone is verified here: the endpoint is unauthenticated and takes a raw E.164, so it
 * also answers whether an account exists for any number. {@code ResolveAbuseFilter} rate-limits it per
 * client and globally, and the decision trace is returned only when
 * {@code gua.resolver.abuse.trace-enabled} is on.
 */
@RestController
public class ResolveController {

    private final ResolutionService resolution;
    private final RosterStore rosterStore;
    private final RoutingClaimsVerifier routingClaimsVerifier;
    private final ResolverProperties.Abuse abuse;
    private final Counter resolveExisting;
    private final Counter resolveRegister;

    public ResolveController(ResolutionService resolution, RosterStore rosterStore,
                             RoutingClaimsVerifier routingClaimsVerifier, ResolverProperties props,
                             MeterRegistry metrics) {
        this.resolution = resolution;
        this.rosterStore = rosterStore;
        this.routingClaimsVerifier = routingClaimsVerifier;
        this.abuse = props.getAbuse();
        // gua_resolver_resolve_total{outcome=...}: existing (login) vs register (new placement).
        this.resolveExisting = Counter.builder("gua.resolver.resolve").tag("outcome", "existing").register(metrics);
        this.resolveRegister = Counter.builder("gua.resolver.resolve").tag("outcome", "register").register(metrics);
    }

    /**
     * Resolve a phone to its existing homeserver (login) or to a placement target (register).
     * An existing account is looked up first; only a phone with no account runs placement. The decision
     * trace is honoured only when the deployment enables it: it names the matched rule, policy id/version
     * and delegated zone, which is policy internals an anonymous caller has no business seeing.
     */
    @PostMapping("/resolve")
    public ResolveResponse resolve(@Valid @RequestBody ResolveRequest request) {
        // The roster version the decision is made against; clients pin and verify this exact version.
        long rosterVersion = rosterStore.current().version();
        boolean trace = abuse.isTraceEnabled() && Boolean.TRUE.equals(request.trace());

        Optional<Homeserver> existing = resolution.resolvePhone(request.phone());
        if (existing.isPresent()) {
            resolveExisting.increment();
            Homeserver hs = existing.get();
            return ResolveResponse.existing(HomeserverRef.of(hs),
                    trace ? DecisionTrace.existing(hs.id(), rosterVersion) : null);
        }

        PlacementDecision decision = resolution.placementDecisionFor(placementContextFor(request));
        resolveRegister.increment();
        return ResolveResponse.register(HomeserverRef.of(decision.homeserver()),
                trace ? DecisionTrace.of(decision, rosterVersion) : null);
    }

    /**
     * Build the placement context for a new-account decision. Institution/OIDC affiliations and attributes
     * are trusted only when they arrive in a signature-verified routing-claims envelope bound to this phone;
     * a public caller's self-asserted {@code affiliations}/{@code attributes} are deliberately dropped.
     * Carrier/geo hints stay, because choosing a carrier homeserver is self-service, not privilege.
     */
    private PlacementContext placementContextFor(ResolveRequest request) {
        RoutingClaimsVerifier.VerifiedRoutingClaims verified =
                routingClaimsVerifier.verify(request.routingClaims(), request.phone());
        // The trust flag comes straight from the verification outcome, never from envelope presence.
        return new PlacementContext(
                request.phone(), request.country(), request.mccmnc(), request.carrier(), request.regionHint(),
                verified.affiliations(), verified.attributes(), verified.verified());
    }

    /**
     * The signed, public roster: what mirrors and clients verify (threshold signatures plus log checkpoint). A
     * mirror serves the upstream document verbatim here, so the upstream signature still covers exactly these
     * bytes, while its own routing uses its verified view of it.
     */
    @GetMapping("/roster")
    public Object roster() {
        return rosterStore.served();
    }

    /**
     * A phone that is not valid E.164 is a client error, not a server fault: answers 400 with a generic
     * message. The phone is never echoed back.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ProblemResponse onInvalidPhone(IllegalArgumentException e) {
        return new ProblemResponse("invalid_phone", e.getMessage());
    }

    @ExceptionHandler(RoutingClaimsVerifier.InvalidRoutingClaimsException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ProblemResponse onInvalidRoutingClaims(RoutingClaimsVerifier.InvalidRoutingClaimsException e) {
        return new ProblemResponse("invalid_routing_claims", e.getMessage());
    }

    @ExceptionHandler(DirectoryUnavailableException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ProblemResponse onDirectoryUnavailable(DirectoryUnavailableException e) {
        return new ProblemResponse("directory_unavailable", "routing directory is temporarily unavailable");
    }

    @ExceptionHandler(NoPlacementAvailableException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ProblemResponse onNoPlacement(NoPlacementAvailableException e) {
        return new ProblemResponse("no_placement_available", "no homeserver is currently accepting new accounts");
    }

    public record ResolveRequest(
            @NotBlank String phone,
            String country,
            String mccmnc,
            String carrier,
            String regionHint,
            List<String> affiliations,
            Map<String, String> attributes,
            RoutingClaimsEnvelope routingClaims,
            Boolean trace) {}

    /** Minimal homeserver reference the client needs to start OIDC; never leaks ":server" to the user. */
    public record HomeserverRef(String serverName, String baseUrl, String masIssuer, String region) {
        static HomeserverRef of(Homeserver hs) {
            return new HomeserverRef(hs.serverName(), hs.baseUrl(), hs.masIssuer(), hs.region());
        }
    }

    public record ResolveResponse(boolean exists, HomeserverRef homeserver, HomeserverRef registerAt,
                                  @JsonInclude(JsonInclude.Include.NON_NULL)
                                  DecisionTrace trace) {
        static ResolveResponse existing(HomeserverRef hs, DecisionTrace trace) {
            return new ResolveResponse(true, hs, null, trace);
        }
        static ResolveResponse register(HomeserverRef hs, DecisionTrace trace) {
            return new ResolveResponse(false, null, hs, trace);
        }
    }

    public record DecisionTrace(String source, String rule, String ruleId, String reason,
                                String policyId, Long policyVersion, String delegatedZoneId,
                                String assignmentPolicy, String homeserverId, Long rosterVersion) {
        static DecisionTrace of(PlacementDecision decision, long rosterVersion) {
            return new DecisionTrace("placement", decision.rule(), decision.ruleId(), decision.reason(),
                    decision.policyId(), decision.policyVersion(), decision.delegatedZoneId(),
                    decision.assignmentPolicy(), decision.homeserver().id(), rosterVersion);
        }

        static DecisionTrace existing(String homeserverId, long rosterVersion) {
            return new DecisionTrace("directory", "directory_lookup", null,
                    "existing account mapping found in active roster", null, null, null, null,
                    homeserverId, rosterVersion);
        }
    }

    public record ProblemResponse(String code, String message) {}
}
