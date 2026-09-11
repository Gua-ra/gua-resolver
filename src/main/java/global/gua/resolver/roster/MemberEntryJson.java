package global.gua.resolver.roster;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

/**
 * Strict transport parsing for member-signed objects (ADM-007). Spring's shared {@code ObjectMapper} ignores
 * unknown properties, so a signed sub-object is read through a dedicated {@link ObjectReader} that rejects
 * unknown fields, duplicate keys, trailing content, nulls for primitives and fractional integers. That keeps
 * a signature from covering fewer fields than a consumer sees. Invalid UTF-8 is already rejected by Jackson's
 * byte parser; strings that are not valid Unicode are rejected by the canonical encoder.
 */
public final class MemberEntryJson {

    private MemberEntryJson() {}

    /** A reader for {@code type} derived from {@code base} (keeps its modules, e.g. java.time) but strict. */
    public static ObjectReader strictReader(ObjectMapper base, Class<?> type) {
        return base.readerFor(type)
                .with(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                        DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES,
                        DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                        DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
                .without(DeserializationFeature.ACCEPT_FLOAT_AS_INT)
                .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    /** Parse raw request bytes as {@code type}, strictly. */
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

    /** Parse an already-read member block strictly; null or JSON null yields null (unattested). */
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

    private static String summary(IOException e) {
        String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        int cut = message.indexOf('\n');
        return cut < 0 ? message : message.substring(0, cut);
    }

    /** A member-signed object that does not parse strictly; it is refused, never partially read. */
    public static class MalformedMemberEntryException extends RuntimeException {
        public MalformedMemberEntryException(String message) {
            super(message);
        }
    }
}
