package global.gua.resolver.governance;

import java.io.IOException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.roster.MemberEntryJson;

/**
 * Strict transport parsing for governance objects, on the same rule ADM-007 sets for member entries: a
 * signed sub-object is read through a reader that refuses unknown fields, duplicate keys and trailing
 * content, so a signature can never cover fewer fields than the resolver goes on to act on.
 *
 * <p>It reuses the member-entry strict reader rather than configuring a second one, so the two can never
 * drift into different notions of strict.
 */
public final class GovernanceJson {

    private GovernanceJson() {}

    /** Parse {@code json} as {@code type}, strictly; anything unparseable is a refused governance object. */
    public static <T> T read(ObjectMapper base, String json, Class<T> type) {
        if (json == null || json.isBlank()) {
            throw new GovernanceException("empty " + type.getSimpleName() + " document");
        }
        try {
            return MemberEntryJson.strictReader(base, type).readValue(json);
        } catch (IOException e) {
            throw new GovernanceException(type.getSimpleName() + " does not parse strictly: " + summary(e));
        }
    }

    /** The same, from an already-parsed node (a sub-object of a larger request body). */
    public static <T> T read(ObjectMapper base, JsonNode node, Class<T> type) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            throw new GovernanceException("missing " + type.getSimpleName());
        }
        try {
            return MemberEntryJson.strictReader(base, type).readValue(node);
        } catch (IOException e) {
            throw new GovernanceException(type.getSimpleName() + " does not parse strictly: " + summary(e));
        }
    }

    private static String summary(IOException e) {
        String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        int cut = message.indexOf('\n');
        return cut < 0 ? message : message.substring(0, cut);
    }
}
