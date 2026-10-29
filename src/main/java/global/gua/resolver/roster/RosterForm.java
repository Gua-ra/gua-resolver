package global.gua.resolver.roster;

import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Which bytes a roster's authority signatures cover. Resolver images before 2026-08-14 sign {@code LEGACY},
 * which leaves each entry's {@code searchVisibility} and {@code searchGroups} out.
 */
public enum RosterForm {
    V1,
    LEGACY;

    /**
     * The form of a served roster, read from its JSON because parsing fills in the search fields: LEGACY when
     * no entry has a {@code searchVisibility} key, V1 when every entry has one, and empty for a mix.
     */
    public static Optional<RosterForm> of(JsonNode roster) {
        int entries = 0;
        int withSearchFields = 0;
        for (JsonNode entry : roster.path("entries")) {
            entries++;
            if (entry.path("homeserver").has("searchVisibility")) {
                withSearchFields++;
            }
        }
        if (withSearchFields == 0) {
            return Optional.of(LEGACY);
        }
        return withSearchFields == entries ? Optional.of(V1) : Optional.empty();
    }
}
