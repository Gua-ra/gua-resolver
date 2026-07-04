package global.gua.resolver.policy;

import java.time.Instant;
import java.util.List;

/**
 * Bounded authority delegation. A rule may reference a zone only when its match is within the zone scope
 * and its target homeserver is explicitly allowed by the zone.
 */
public record DelegationZone(
        String id,
        ScopeType scopeType,
        String scopeValue,
        String delegatedAuthority,
        List<String> allowedHomeserverIds,
        Instant notBefore,
        Instant expiresAt) {

    public enum ScopeType {
        PHONE_PREFIX,
        INSTITUTION_DOMAIN,
        OIDC_ISSUER,
        ATTRIBUTE
    }
}
