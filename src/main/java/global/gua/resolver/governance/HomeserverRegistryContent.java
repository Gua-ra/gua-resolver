package global.gua.resolver.governance;

import java.util.List;

/**
 * The content a {@code HomeserverRegistry} epoch commits to: the full membership as governance sets it.
 *
 * <p>It is a complete statement, not a delta. An epoch that omits a member is an epoch in which that member
 * has no governed status, so the set is always read as a whole and a member cannot be dropped silently
 * between epochs.
 *
 * <p>The epoch object carries only this content's hash. Transporting the content beside the epoch and
 * re-deriving the hash is what lets the resolver check that the signed hash is the membership it actually
 * built, rather than a hash it has no way to interpret.
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
