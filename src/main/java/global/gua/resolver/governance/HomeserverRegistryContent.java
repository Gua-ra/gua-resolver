package global.gua.resolver.governance;

import java.util.List;

/**
 * The content a {@code HomeserverRegistry} epoch commits to: the full membership as governance sets it.
 *
 * <p>It is a complete statement, not a delta. An epoch that omits a member is an epoch in which that member
 * has no governed status, so the set is always read as a whole and a member cannot be dropped silently
 * between epochs. The epoch object carries only this content's hash.
 */
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
