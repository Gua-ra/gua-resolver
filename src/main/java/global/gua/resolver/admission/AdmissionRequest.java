package global.gua.resolver.admission;

import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.roster.MemberAttestation;

/**
 * An operator's application to join the federation. The authority vets it before admitting: proof of control
 * over the registered Ed25519 signing key, a domain-ownership proof, and validation that the requested claim
 * predicates do not overlap an existing entry.
 *
 * @param id                 desired stable federation id (optional; derived from serverName if absent)
 * @param serverName         Matrix server_name being admitted
 * @param baseUrl            client base URL
 * @param masIssuer          the homeserver's MAS OIDC issuer
 * @param region             optional region/tenant tag
 * @param weight             load-spreading weight for placement (>= 0)
 * @param acceptsNew         whether it should receive new-account placement
 * @param signingKey         the operator's Ed25519 public key, base64 X.509 (the membership credential)
 * @param keyPossessionProof base64 Ed25519 signature over {@code serverName}, proving control of signingKey;
 *                           required only without a member block, which proves possession by signing the
 *                           entry itself
 * @param domainProof        domain-ownership proof token (verified by the DomainOwnershipVerifier)
 * @param claims             requested declarative placement claims (authority validates non-overlap)
 * @param searchVisibility   optional user-search discoverability: GLOBAL (default), SERVER, or GROUP
 * @param searchGroups       search-group ids; required (non-empty) when searchVisibility is GROUP
 * @param member             optional member self-signature over the entry being admitted. With it, {@code id}
 *                           is required (it is signed) and {@code keyPossessionProof} is not; without it the
 *                           legacy path applies, which is refused once
 *                           {@code gua.resolver.roster.require-member-signature} is on
 */
public record AdmissionRequest(
        String id,
        @NotBlank String serverName,
        @NotBlank String baseUrl,
        @NotBlank String masIssuer,
        String region,
        int weight,
        boolean acceptsNew,
        @NotBlank String signingKey,
        String keyPossessionProof,
        @NotBlank String domainProof,
        @NotNull List<ClaimPredicate> claims,
        String searchVisibility,
        List<String> searchGroups,
        MemberAttestation member) {

    /** Legacy shape: no member self-signature. */
    public AdmissionRequest(String id, String serverName, String baseUrl, String masIssuer, String region,
                            int weight, boolean acceptsNew, String signingKey, String keyPossessionProof,
                            String domainProof, List<ClaimPredicate> claims, String searchVisibility,
                            List<String> searchGroups) {
        this(id, serverName, baseUrl, masIssuer, region, weight, acceptsNew, signingKey, keyPossessionProof,
                domainProof, claims, searchVisibility, searchGroups, null);
    }
}
