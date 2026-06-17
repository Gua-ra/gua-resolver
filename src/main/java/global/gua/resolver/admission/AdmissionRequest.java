package global.gua.resolver.admission;

import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import global.gua.resolver.placement.ClaimPredicate;

/**
 * An operator's application to join the federation (§3 step 1). The authority vets it before admitting:
 * proof of control over the registered Ed25519 signing key (the membership credential), a domain-ownership
 * proof, and validation that the requested claim predicates don't overlap an existing entry.
 *
 * @param id                 desired stable federation id (optional; derived from serverName if absent)
 * @param serverName         Matrix server_name being admitted
 * @param baseUrl            client base URL
 * @param masIssuer          the homeserver's MAS OIDC issuer
 * @param region             optional region/tenant tag
 * @param weight             load-spreading weight for placement (>= 0)
 * @param acceptsNew         whether it should receive NEW account placement
 * @param signingKey         the operator's Ed25519 public key, base64 X.509 (the membership credential)
 * @param keyPossessionProof base64 Ed25519 signature over {@code serverName}, proving control of signingKey
 * @param domainProof        domain-ownership proof token (verified by the DomainOwnershipVerifier)
 * @param claims             requested declarative placement claims (authority validates non-overlap)
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
        @NotBlank String keyPossessionProof,
        @NotBlank String domainProof,
        @NotNull List<ClaimPredicate> claims) {
}
