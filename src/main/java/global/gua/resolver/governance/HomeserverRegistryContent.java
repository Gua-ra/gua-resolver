package global.gua.resolver.governance;

import java.util.List;

/** A complete membership statement, not a delta. */
public record HomeserverRegistryContent(String schema, List<RegistryMember> members) {

    public static final String SCHEMA = "gua-homeserver-registry-content.v1";

    public HomeserverRegistryContent {
        members = members == null ? List.of() : List.copyOf(members);
    }

    public static HomeserverRegistryContent of(List<RegistryMember> members) {
        return new HomeserverRegistryContent(SCHEMA, members);
    }

    public void validateShape() {
        if (!SCHEMA.equals(schema)) {
            throw new GovernanceException("unsupported registry content schema: " + schema);
        }
        members.forEach(RegistryMember::validateShape);
    }
}
