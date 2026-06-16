package global.gua.resolver.roster;

import java.time.Instant;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import global.gua.resolver.domain.Homeserver;

/**
 * Phase-1 dev RosterStore: a single homeserver read from config, with an empty signature set and a stub log
 * checkpoint. It lets the resolver run end-to-end against the dev homeserver while the real authority-signed,
 * transparency-logged store (and mirror variant) is built. NOT for production — replace with the signed
 * store before a second operator joins. See docs/FEDERATION_ROUTING_DESIGN.md §5.
 */
@Component
public class InMemoryRosterStore implements RosterStore {

    private final SignedRoster roster;

    public InMemoryRosterStore(
            @Value("${gua.resolver.dev-homeserver.id:dev}") String id,
            @Value("${gua.resolver.dev-homeserver.server-name:gua.local}") String serverName,
            @Value("${gua.resolver.dev-homeserver.base-url:https://matrix.gua.local}") String baseUrl,
            @Value("${gua.resolver.dev-homeserver.mas-issuer:https://account.gua.local}") String masIssuer,
            @Value("${gua.resolver.dev-homeserver.region:dev}") String region) {
        Homeserver hs = new Homeserver(id, serverName, baseUrl, masIssuer, region, 1, true, null);
        RosterEntry entry = new RosterEntry(hs, List.of(), Instant.now(), RosterEntry.Status.ACTIVE);
        this.roster = new SignedRoster(
                1L, Instant.now(), List.of(entry),
                new SignedRoster.LogCheckpoint("dev-stub", 1L),
                List.of()); // unsigned in dev; threshold signatures arrive with the authority store
    }

    @Override
    public SignedRoster current() {
        return roster;
    }

    @Override
    public SignedRoster refresh() {
        return roster;
    }
}
