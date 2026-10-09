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
import global.gua.resolver.directory.PhoneHasher;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.NoPlacementAvailableException;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.service.HomeserverUnavailableException;
import global.gua.resolver.service.ResolutionService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * The federation front door consumed by the iOS and Android clients BEFORE OIDC login. The client sends a
 * phone number and learns which homeserver to authenticate against: the one holding its account, or where
 * to register. Nothing about the phone is verified here: the endpoint is unauthenticated and takes a raw
 * E.164, so the answer must not say whether the number has an account. Interim controls:
 * {@code global.gua.resolver.abuse.ResolveAbuseFilter} rate-limits the endpoint per client and globally,
 * and the decision trace is returned only when {@code gua.resolver.abuse.trace-enabled} is on. This is what
 * replaces the clients' hardcoded {@code GuaDefaultAccountProvider}.
 *
 * <p>Read-mostly and cacheable. Designed to run as a mirrorable fleet; both deployed environments run a
 * single node today (ADM-001 O12).
 */
@RestController
public class ResolveController {

    private final ResolutionService resolution;
    private final RosterStore rosterStore;
    private final RoutingClaimsVerifier routingClaimsVerifier;
    private final ResolverProperties.Abuse abuse;
    private final Counter resolveExisting;
    private final Counter resolveRegister;
    private final Counter resolveUnavailable;

    public ResolveController(ResolutionService resolution, RosterStore rosterStore,
                             RoutingClaimsVerifier routingClaimsVerifier, ResolverProperties props,
                             MeterRegistry metrics) {
        this.resolution = resolution;
        this.rosterStore = rosterStore;
        this.routingClaimsVerifier = routingClaimsVerifier;
        this.abuse = props.getAbuse();
        // gua_resolver_resolve_total{outcome=...}: existing account, new placement, or an existing account
        // whose homeserver is not ACTIVE.
        this.resolveExisting = Counter.builder("gua.resolver.resolve").tag("outcome", "existing").register(metrics);
        this.resolveRegister = Counter.builder("gua.resolver.resolve").tag("outcome", "register").register(metrics);
        this.resolveUnavailable = Counter.builder("gua.resolver.resolve")
                .tag("outcome", "homeserver_unavailable").register(metrics);
    }

    /**
     * Resolve a phone to the homeserver the client should authenticate against: the account's homeserver
     * when the directory has one, otherwise the placement target. Both cases return the same shape, and
     * both run placement and read the roster the same number of times so the work done matches. A directory
     * row whose homeserver is not ACTIVE answers 503 and never falls through to placement. The decision
     * trace is honoured only when the deployment enables it, because it exposes the directory hit or the
     * matched rule, policy id/version and delegated zone to anonymous callers.
     */
    @PostMapping("/resolve")
    public ResolveResponse resolve(@Valid @RequestBody ResolveRequest request) {
        // The roster version the decision is made against; clients pin + verify this exact version.
        SignedRoster roster = rosterStore.current();
        long rosterVersion = roster.version();
        boolean trace = abuse.isTraceEnabled() && Boolean.TRUE.equals(request.trace());

        // Placement must see the number the directory keys on, or padding the phone moves a miss but not a hit.
        String phone = PhoneHasher.normalize(request.phone());
        Optional<Homeserver> existing = resolution.resolvePhone(phone, roster);
        PlacementDecision decision = placementDecisionFor(request, phone, existing.isPresent());

        if (existing.isPresent()) {
            resolveExisting.increment();
            Homeserver hs = existing.get();
            return ResolveResponse.of(HomeserverRef.of(hs),
                    trace ? DecisionTrace.existing(hs.id(), rosterVersion) : null);
        }
        resolveRegister.increment();
        return ResolveResponse.of(HomeserverRef.of(decision.homeserver()),
                trace ? DecisionTrace.of(decision, rosterVersion) : null);
    }

    /**
     * Placement for this request. With an existing account the result is unused, and a placement failure
     * is ignored so the account can still sign in while no homeserver accepts new accounts.
     */
    private PlacementDecision placementDecisionFor(ResolveRequest request, String phone, boolean accountExists) {
        try {
            return resolution.placementDecisionFor(placementContextFor(request, phone));
        } catch (NoPlacementAvailableException e) {
            if (accountExists) {
                return null;
            }
            throw e;
        }
    }

    /**
     * Institution/OIDC affiliations and attributes are trusted ONLY from a signature-verified routing-claims
     * envelope bound to this phone; the top-level self-asserted {@code affiliations}/{@code attributes} are
     * dropped. Carrier/geo hints stay, because choosing a carrier homeserver is self-service, not privilege.
     */
    private PlacementContext placementContextFor(ResolveRequest request, String phone) {
        RoutingClaimsVerifier.VerifiedRoutingClaims verified =
                routingClaimsVerifier.verify(request.routingClaims(), phone);
        // The trust flag comes straight from the verification outcome, never from envelope presence.
        return new PlacementContext(
                phone, request.country(), request.mccmnc(), request.carrier(), request.regionHint(),
                verified.affiliations(), verified.attributes(), verified.verified());
    }

    /**
     * The signed, public roster: what mirrors and clients verify (threshold sigs + log checkpoint). A mirror
     * serves the upstream document verbatim here, so the upstream signature still covers exactly these bytes,
     * while its own routing uses its verified view of it (ADM-007).
     */
    @GetMapping("/roster")
    public Object roster() {
        return rosterStore.served();
    }

    /**
     * A phone that isn't valid E.164 is a client error, not a server fault. Map it to 400 so callers
     * get a clear "fix your input" signal (and a friendly message) instead of an opaque 500. The phone
     * is never echoed back, only a generic, non-PII message.
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

    @ExceptionHandler(HomeserverUnavailableException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ProblemResponse onHomeserverUnavailable(HomeserverUnavailableException e) {
        resolveUnavailable.increment();
        return new ProblemResponse("homeserver_unavailable", "this account's homeserver is temporarily unavailable");
    }

    // --- DTOs -----------------------------------------------------------------------------------

    /** The /resolve request body. A plain data carrier; all logic lives in the controller/service. */
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

    /**
     * {@code exists} is always false and {@code homeserver} always null: deployed clients still decode both
     * and take the target from {@code registerAt} when {@code exists} is false.
     */
    public record ResolveResponse(boolean exists, HomeserverRef homeserver, HomeserverRef registerAt,
                                  @JsonInclude(JsonInclude.Include.NON_NULL)
                                  DecisionTrace trace) {
        static ResolveResponse of(HomeserverRef target, DecisionTrace trace) {
            return new ResolveResponse(false, null, target, trace);
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
