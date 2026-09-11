package global.gua.resolver.admission;

import java.util.List;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.MemberAttestation;

/**
 * A member's attestation of its own roster entry, submitted to
 * {@code POST /authority/roster/{id}/member} (ADM-007). The body carries only what the member signs: the
 * authority keeps weight, acceptsNew, claims and status. It is parsed strictly, so an unknown field is
 * refused rather than silently dropped outside the signature.
 *
 * <p>{@code serverName} must equal the stored one: changing it is a new identity, not an update. The signing
 * key must be the stored key, or a new key whose entry is also signed by the stored one (rotation).
 *
 * @param homeserver the signed field set; {@code id}, when present, must equal the path id
 * @param member     the attestation metadata and its signatures
 */
public record MemberAttestationRequest(HomeserverFields homeserver, MemberAttestation member) {

    /**
     * @param id               optional; the signed homeserver id, which must equal the path id
     * @param serverName       the member's Matrix server_name, unchanged from the stored entry
     * @param baseUrl          client base URL
     * @param masIssuer        the homeserver's MAS OIDC issuer
     * @param signingKey       the member's Ed25519 public key, base64 X.509
     * @param region           optional region tag; absent and empty are different signed bytes
     * @param searchVisibility GLOBAL, SERVER or GROUP, by exact name
     * @param searchGroups     search-group ids; required (non-empty) when searchVisibility is GROUP
     */
    public record HomeserverFields(
            String id,
            String serverName,
            String baseUrl,
            String masIssuer,
            String signingKey,
            String region,
            Homeserver.SearchVisibility searchVisibility,
            List<String> searchGroups) {}
}
