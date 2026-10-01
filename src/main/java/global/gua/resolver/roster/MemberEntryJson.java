package global.gua.resolver.roster;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

import global.gua.resolver.domain.Homeserver;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Strict parsing: unknown fields, duplicate keys and trailing content are refused in signed objects. */
public final class MemberEntryJson {

    private MemberEntryJson() {}

    public static ObjectReader strictReader(ObjectMapper base, Class<?> type) {
        return base.readerFor(type)
                .with(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                        DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES,
                        DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                        DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
                .without(DeserializationFeature.ACCEPT_FLOAT_AS_INT)
                .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    public static <T> T read(ObjectMapper base, byte[] json, Class<T> type) {
        if (json == null || json.length == 0) {
            throw new MalformedMemberEntryException("empty body");
        }
        try {
            return strictReader(base, type).readValue(json);
        } catch (IOException e) {
            throw new MalformedMemberEntryException(summary(e));
        }
    }

    public static MemberAttestation readMember(ObjectMapper base, JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        try {
            return strictReader(base, MemberAttestation.class).readValue(node);
        } catch (IOException e) {
            throw new MalformedMemberEntryException(summary(e));
        }
    }

    public static JsonNode readTree(ObjectMapper base, String json) {
        try {
            return base.reader().with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION).readTree(json);
        } catch (IOException e) {
            throw new MalformedMemberEntryException(summary(e));
        }
    }

    public static JsonNode readTree(ObjectMapper base, byte[] json) {
        if (json == null || json.length == 0) {
            throw new MalformedMemberEntryException("empty body");
        }
        try {
            return base.reader().with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION).readTree(json);
        } catch (IOException e) {
            throw new MalformedMemberEntryException(summary(e));
        }
    }

    public static Set<String> malformedMemberEntries(ObjectMapper base, JsonNode rosterTree) {
        Set<String> malformed = new LinkedHashSet<>();
        for (JsonNode entry : rosterTree.path("entries")) {
            JsonNode member = entry.path("member");
            if (member.isMissingNode() || member.isNull()) {
                continue;
            }
            try {
                readMember(base, member);
            } catch (MalformedMemberEntryException e) {
                malformed.add(entry.path("homeserver").path("id").asText());
            }
        }
        return malformed;
    }

    public static String signedFields(ObjectMapper base, Homeserver homeserver, MemberAttestation member) {
        ObjectNode root = base.createObjectNode();
        ObjectNode hs = root.putObject("homeserver");
        hs.put("id", homeserver.id());
        hs.put("serverName", homeserver.serverName());
        hs.put("baseUrl", homeserver.baseUrl());
        hs.put("masIssuer", homeserver.masIssuer());
        hs.put("signingKey", homeserver.signingKey());
        if (homeserver.region() == null) {
            hs.putNull("region");
        } else {
            hs.put("region", homeserver.region());
        }
        hs.put("searchVisibility", homeserver.searchVisibility().name());
        hs.set("searchGroups", base.valueToTree(homeserver.searchGroups()));
        ObjectNode m = root.putObject("member");
        m.put("schema", member.schema());
        m.put("alg", member.alg());
        m.put("keyId", member.keyId());
        m.put("sequence", member.sequence());
        m.put("notBefore", member.notBefore().toString());
        m.put("notAfter", member.notAfter().toString());
        return root.toString();
    }

    private static String summary(IOException e) {
        String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        int cut = message.indexOf('\n');
        return cut < 0 ? message : message.substring(0, cut);
    }

    public static class MalformedMemberEntryException extends RuntimeException {
        public MalformedMemberEntryException(String message) {
            super(message);
        }
    }
}
