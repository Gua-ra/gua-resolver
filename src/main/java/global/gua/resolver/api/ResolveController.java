package global.gua.resolver.api;

import java.util.List;
import java.util.Map;

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
 * The federation front door consumed by iOS / Web / Android BEFORE OIDC login. The client sends a
 * verified phone and learns which homeserver to authenticate against; for a new phone it learns where to
 * register. This is what replaces the clients' hardcoded {@code GuaDefaultAccountProvider}.
 *
 * <p>Read-mostly and cacheable — the service is designed to run as a horizontally-scaled, mirrorable fleet.
 */
@RestController
public class ResolveController {

    private final ResolutionService resolution;
    private final RosterStore rosterStore;
    private final RoutingClaimsVerifier routingClaimsVerifier;
    private final Counter resolveExisting;
    private final Counter resolveRegister;

    public ResolveController(ResolutionService resolution, RosterStore rosterStore,
                             RoutingClaimsVerifier routingClaimsVerifier, MeterRegistry metrics) {
        this.resolution = resolution;
        this.rosterStore = rosterStore;
        this.routingClaimsVerifier = routingClaimsVerifier;
        // gua_resolver_resolve_total{outcome=...} — login (existing account) vs register (new placement).
        this.resolveExisting = Counter.builder("gua.resolver.resolve").tag("outcome", "existing").register(metrics);
        this.resolveRegister = Counter.builder("gua.resolver.resolve").tag("outcome", "register").register(metrics);
    }

    /** Resolve a phone to its homeserver (login) or to a placement target (register). */
    @PostMapping("/resolve")
    public ResolveResponse resolve(@Valid @RequestBody ResolveRequest request) {
        // The roster version the decision is made against; clients pin + verify this exact version.
        long rosterVersion = rosterStore.current().version();
        return resolution.resolvePhone(request.phone())
                .map(hs -> {
                    resolveExisting.increment();
                    return ResolveResponse.existing(HomeserverRef.of(hs), request.traceEnabled()
                            ? DecisionTrace.existing(hs.id(), rosterVersion) : null);
                })
                .orElseGet(() -> {
                    PlacementDecision decision = resolution.placementDecisionFor(
                            request.toPlacementContext(routingClaimsVerifier));
                    Homeserver target = decision.homeserver();
                    resolveRegister.increment();
                    return ResolveResponse.register(HomeserverRef.of(target), request.traceEnabled()
                            ? DecisionTrace.of(decision, rosterVersion) : null);
                });
    }

    /** The signed, public roster — what mirrors and clients verify (threshold sigs + log checkpoint). */
    @GetMapping("/roster")
    public Object roster() {
        return rosterStore.current();
    }

    /**
     * A phone that isn't valid E.164 is a client error, not a server fault. Map it to 400 so callers
     * get a clear "fix your input" signal (and a friendly message) instead of an opaque 500. The phone
     * is never echoed back — only a generic, non-PII message.
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

    // --- DTOs -----------------------------------------------------------------------------------

    public record ResolveRequest(
            @NotBlank String phone,
            String country,
            String mccmnc,
            String carrier,
            String regionHint,
            List<String> affiliations,
            Map<String, String> attributes,
            RoutingClaimsEnvelope routingClaims,
            Boolean trace) {

        PlacementContext toPlacementContext(RoutingClaimsVerifier verifier) {
            // Institution/OIDC affiliations and attributes are trusted ONLY from a signature-verified
            // envelope bound to this phone. Self-asserted request.affiliations / request.attributes are
            // deliberately NOT carried into the placement context: they were the self-assertion vector that
            // let an anonymous caller obtain institutional placement. Carrier/geo hints (country, mccmnc,
            // carrier, regionHint) stay, because choosing a carrier homeserver is self-service, not privilege.
            RoutingClaimsVerifier.VerifiedRoutingClaims verified = verifier.verify(routingClaims, phone);
            boolean claimsVerified = routingClaims != null;
            List<String> effectiveAffiliations = claimsVerified ? verified.affiliations() : List.of();
            Map<String, String> effectiveAttributes = claimsVerified ? verified.attributes() : Map.of();
            return new PlacementContext(phone, country, mccmnc, carrier, regionHint,
                    effectiveAffiliations, effectiveAttributes, claimsVerified);
        }

        boolean traceEnabled() {
            return Boolean.TRUE.equals(trace);
        }
    }

    /** Minimal homeserver reference the client needs to start OIDC — never leaks ":server" to the user. */
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

    /** Problem payload for client errors (mirrors the shape used by the other API controllers). */
    public record ProblemResponse(String code, String message) {}
}
