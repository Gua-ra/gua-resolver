package global.gua.resolver.admission;

import java.util.List;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.MemberAttestation;

public record MemberAttestationRequest(HomeserverFields homeserver, MemberAttestation member) {

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
