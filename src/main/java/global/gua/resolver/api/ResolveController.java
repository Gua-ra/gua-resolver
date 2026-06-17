package global.gua.resolver.api;

import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.service.ResolutionService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * The federation front door consumed by iOS / web (and later Android) BEFORE OIDC login. The client sends a
 * verified phone and learns which homeserver to authenticate against; for a new phone it learns where to
 * register. This is what replaces the clients' hardcoded {@code GuaDefaultAccountProvider}.
 *
 * <p>Read-mostly and cacheable — the service is designed to run as a horizontally-scaled, mirrorable fleet.
 */
@RestController
public class ResolveController {

    private final ResolutionService resolution;
    private final RosterStore rosterStore;
    private final Counter resolveExisting;
    private final Counter resolveRegister;

    public ResolveController(ResolutionService resolution, RosterStore rosterStore, MeterRegistry metrics) {
        this.resolution = resolution;
        this.rosterStore = rosterStore;
        // gua_resolver_resolve_total{outcome=...} — login (existing account) vs register (new placement).
        this.resolveExisting = Counter.builder("gua.resolver.resolve").tag("outcome", "existing").register(metrics);
        this.resolveRegister = Counter.builder("gua.resolver.resolve").tag("outcome", "register").register(metrics);
    }

    /** Resolve a phone to its homeserver (login) or to a placement target (register). */
    @PostMapping("/resolve")
    public ResolveResponse resolve(@RequestBody ResolveRequest request) {
        return resolution.resolvePhone(request.phone())
                .map(hs -> {
                    resolveExisting.increment();
                    return ResolveResponse.existing(HomeserverRef.of(hs));
                })
                .orElseGet(() -> {
                    Homeserver target = resolution.placementFor(PlacementContext.forPhone(request.phone()));
                    resolveRegister.increment();
                    return ResolveResponse.register(HomeserverRef.of(target));
                });
    }

    /** The signed, public roster — what mirrors and clients verify (threshold sigs + log checkpoint). */
    @GetMapping("/roster")
    public Object roster() {
        return rosterStore.current();
    }

    // --- DTOs -----------------------------------------------------------------------------------

    public record ResolveRequest(@NotBlank String phone) {}

    /** Minimal homeserver reference the client needs to start OIDC — never leaks ":server" to the user. */
    public record HomeserverRef(String serverName, String baseUrl, String masIssuer, String region) {
        static HomeserverRef of(Homeserver hs) {
            return new HomeserverRef(hs.serverName(), hs.baseUrl(), hs.masIssuer(), hs.region());
        }
    }

    public record ResolveResponse(boolean exists, HomeserverRef homeserver, HomeserverRef registerAt) {
        static ResolveResponse existing(HomeserverRef hs) { return new ResolveResponse(true, hs, null); }
        static ResolveResponse register(HomeserverRef hs) { return new ResolveResponse(false, null, hs); }
    }
}
