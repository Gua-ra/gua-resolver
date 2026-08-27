package global.gua.resolver.domain;

import java.util.List;

/**
 * A federated Gua homeserver, as advertised in the signed roster.
 *
 * @param id               stable federation id (never the Matrix domain directly)
 * @param serverName       Matrix server_name (e.g. usp.gua.global)
 * @param baseUrl          client base URL (what a client uses to talk to it)
 * @param masIssuer        the homeserver's MAS OIDC issuer (for the client's OIDC login)
 * @param region           optional region/tenant tag used by placement policy
 * @param weight           load-spreading weight for weighted placement (>= 0)
 * @param acceptsNew       whether this homeserver currently accepts NEW account placement
 * @param signingKey       the homeserver's Ed25519 public key (base64), anchored to its Matrix signing key
 * @param searchVisibility who may discover this homeserver's users via federated username search; part of
 *                         the signed roster so the policy is authority-attested and client-verifiable
 * @param searchGroups     search-group ids; used only when {@code searchVisibility} is {@code GROUP}
 */
public record Homeserver(
        String id,
        String serverName,
        String baseUrl,
        String masIssuer,
        String region,
        int weight,
        boolean acceptsNew,
        String signingKey,
        SearchVisibility searchVisibility,
        List<String> searchGroups) {

    /** Discoverability of this homeserver's users in federated username search. */
    public enum SearchVisibility { GLOBAL, SERVER, GROUP }

    public Homeserver {
        // Tolerate older payloads (mirrors, cached rosters) that predate these fields.
        if (searchVisibility == null) {
            searchVisibility = SearchVisibility.GLOBAL;
        }
        searchGroups = searchGroups == null ? List.of() : List.copyOf(searchGroups);
    }

    /** Pre-search-visibility shape: defaults to {@code GLOBAL} discoverability, no groups. */
    public Homeserver(String id, String serverName, String baseUrl, String masIssuer, String region,
                      int weight, boolean acceptsNew, String signingKey) {
        this(id, serverName, baseUrl, masIssuer, region, weight, acceptsNew, signingKey,
                SearchVisibility.GLOBAL, List.of());
    }
}
