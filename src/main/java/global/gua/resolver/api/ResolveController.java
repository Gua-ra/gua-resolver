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

/** Unauthenticated: reveals whether an account exists for any number; rate limiting is the only control. */
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
        this.resolveExisting = Counter.builder("gua.resolver.resolve").tag("outcome", "existing").register(metrics);
        this.resolveRegister = Counter.builder("gua.resolver.resolve").tag("outcome", "register").register(metrics);
    }

    @PostMapping("/resolve")
    public ResolveResponse resolve(@Valid @RequestBody ResolveRequest request) {
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

    private PlacementContext placementContextFor(ResolveRequest request) {
        RoutingClaimsVerifier.VerifiedRoutingClaims verified =
                routingClaimsVerifier.verify(request.routingClaims(), request.phone());
        return new PlacementContext(
                request.phone(), request.country(), request.mccmnc(), request.carrier(), request.regionHint(),
                verified.affiliations(), verified.attributes(), verified.verified());
    }

    @GetMapping("/roster")
    public Object roster() {
        return rosterStore.served();
    }

    /** The phone is never echoed back. */
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
