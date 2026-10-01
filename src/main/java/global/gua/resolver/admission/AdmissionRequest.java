package global.gua.resolver.admission;

import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.roster.MemberAttestation;

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

    public AdmissionRequest(String id, String serverName, String baseUrl, String masIssuer, String region,
                            int weight, boolean acceptsNew, String signingKey, String keyPossessionProof,
                            String domainProof, List<ClaimPredicate> claims, String searchVisibility,
                            List<String> searchGroups) {
        this(id, serverName, baseUrl, masIssuer, region, weight, acceptsNew, signingKey, keyPossessionProof,
                domainProof, claims, searchVisibility, searchGroups, null);
    }
}
