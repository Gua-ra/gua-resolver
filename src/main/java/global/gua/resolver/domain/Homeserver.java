package global.gua.resolver.domain;

import java.util.List;

public record Homeserver(
        String id,
        String serverName,
        String baseUrl,
        String masIssuer,
        String region,
        int weight,
        boolean acceptsNew,
        String signingKey,
        SearchVisibility searchVisibility,
        List<String> searchGroups) {

    public enum SearchVisibility { GLOBAL, SERVER, GROUP }

    public Homeserver {
        // Older payloads predate these fields.
        if (searchVisibility == null) {
            searchVisibility = SearchVisibility.GLOBAL;
        }
        searchGroups = searchGroups == null ? List.of() : List.copyOf(searchGroups);
    }

    public Homeserver(String id, String serverName, String baseUrl, String masIssuer, String region,
                      int weight, boolean acceptsNew, String signingKey) {
        this(id, serverName, baseUrl, masIssuer, region, weight, acceptsNew, signingKey,
                SearchVisibility.GLOBAL, List.of());
    }
}
