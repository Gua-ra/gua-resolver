package global.gua.resolver.policy;

import java.time.Instant;
import java.util.List;

/**
 * A rule may reference a zone only when its match is within the zone scope and its target is allowed by the
 * zone. It is trusted only when the authority signed the bundle and the zone's delegate signed its rules.
 */
public record DelegationZone(
        String id,
        ScopeType scopeType,
        String scopeValue,
        String delegatedAuthority,
        String delegateKeyId,
        String delegatePublicKey,
        List<String> allowedHomeserverIds,
        Instant notBefore,
        Instant expiresAt) {

    public boolean inEffectAt(Instant at) {
        return ValidityWindow.contains(notBefore, expiresAt, at);
    }

    public enum ScopeType {
        PHONE_PREFIX,
        INSTITUTION_DOMAIN,
        OIDC_ISSUER,
        ATTRIBUTE
    }
}
