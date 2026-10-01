package global.gua.resolver.policy;

import java.time.Instant;
import java.util.List;

/** A zone's rules are trusted only when the bundle is authority-signed and delegateKeyId signed the rules. */
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

    public enum ScopeType {
        PHONE_PREFIX,
        INSTITUTION_DOMAIN,
        OIDC_ISSUER,
        ATTRIBUTE
    }
}
