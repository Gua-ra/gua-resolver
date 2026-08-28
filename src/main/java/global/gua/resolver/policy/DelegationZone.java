package global.gua.resolver.policy;

import java.time.Instant;
import java.util.List;

/**
 * Bounded authority delegation. A rule may reference a zone only when its match is within the zone scope
 * and its target homeserver is explicitly allowed by the zone.
 *
 * <p>Cryptographic delegation: the authority threshold-signs the whole bundle, which ATTESTS this zone's
 * grant (its scope, allowed homeservers, validity, and the delegate's public key {@code delegatePublicKey}
 * identified by {@code delegateKeyId}). The delegate then signs the rules inside this zone with that key
 * (see {@code RoutingPolicyBundle.delegateSignatures}). A rule is trusted only when BOTH hold, so a delegate
 * controls its own rules within an authority-granted scope and nobody can forge them. A zone whose
 * {@code delegateKeyId} is an authority key is authority self-delegation (e.g. public onboarding rules).
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

    public enum ScopeType {
        PHONE_PREFIX,
        INSTITUTION_DOMAIN,
        OIDC_ISSUER,
        ATTRIBUTE
    }
}
