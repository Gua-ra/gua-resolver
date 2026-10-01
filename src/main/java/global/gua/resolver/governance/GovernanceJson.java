package global.gua.resolver.governance;

import java.io.IOException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.roster.MemberEntryJson;

public final class GovernanceJson {

    private GovernanceJson() {}

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
