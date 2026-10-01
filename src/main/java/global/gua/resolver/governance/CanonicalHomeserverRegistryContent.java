package global.gua.resolver.governance;

import java.util.List;
import java.util.Map;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.placement.ClaimPredicate;

/** Members are sorted by homeserverId; claims keep the order that was signed. */
public final class CanonicalHomeserverRegistryContent {

    private CanonicalHomeserverRegistryContent() {}

    public static byte[] bytes(HomeserverRegistryContent content) {
        if (content == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("registry content is required");
        }
        List<RegistryMember> members = CanonicalOrder.sortedUnique(content.members(),
                RegistryMember::homeserverId, "registry member");
        CanonicalEncoder e = CanonicalEncoder.begin(HomeserverRegistryContent.SCHEMA)
                .listCount(members.size());
        for (RegistryMember m : members) {
            e.string(m.homeserverId())
                    .enumName(m.status())
                    .optionalString(m.memberEntryHash())
                    .int64(m.weight())
                    .bool(m.acceptsNew())
                    .listCount(m.claims().size());
            for (ClaimPredicate claim : m.claims()) {
                claim(e, claim);
            }
        }
        return e.toByteArray();
    }

    public static String hash(HomeserverRegistryContent content) {
        return CanonicalEncoder.sha256Hex(bytes(content));
    }

    private static void claim(CanonicalEncoder e, ClaimPredicate c) {
        if (c == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("claim must not be null");
        }
        e.optionalString(c.country())
                .optionalString(c.mccmnc())
                .optionalString(c.carrier())
                .stringSet(c.phonePrefixes() == null ? List.of() : c.phonePrefixes())
                .optionalString(c.affiliation());
        Map<String, String> attributes = c.attributeMatch() == null ? Map.of() : c.attributeMatch();
        List<String> keys = CanonicalOrder.sortedUnique(attributes.keySet(), k -> k, "attributeMatch key");
        e.listCount(keys.size());
        for (String key : keys) {
            String value = attributes.get(key);
            if (value == null) {
                throw new CanonicalEncoder.CanonicalEncodingException(
                        "attributeMatch value for " + key + " is null");
            }
            e.string(key).string(value);
        }
        e.optionalString(c.remoteClaimUrl()).int64(c.priority());
    }
}
