package global.gua.resolver.domain;

/**
 * A federated Gua homeserver, as advertised in the signed roster.
 *
 * @param id          stable federation id (never the Matrix domain directly)
 * @param serverName  Matrix server_name (e.g. usp.gua.global)
 * @param baseUrl     client base URL (what a client uses to talk to it)
 * @param masIssuer   the homeserver's MAS OIDC issuer (for the client's OIDC login)
 * @param region      optional region/tenant tag used by placement policy
 * @param weight      load-spreading weight for weighted placement (>= 0)
 * @param acceptsNew  whether this homeserver currently accepts NEW account placement
 * @param signingKey  the homeserver's Ed25519 public key (base64), anchored to its Matrix signing key
 */
public record Homeserver(
        String id,
        String serverName,
        String baseUrl,
        String masIssuer,
        String region,
        int weight,
        boolean acceptsNew,
        String signingKey) {
}
