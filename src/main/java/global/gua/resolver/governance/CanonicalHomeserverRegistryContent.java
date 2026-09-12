package global.gua.resolver.governance;

import java.util.List;
import java.util.Map;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.placement.ClaimPredicate;

/**
 * The {@code gua-homeserver-registry-content.v1} canonical bytes, encoded with {@code gua-lp.v1} (ADM-007).
 * This is the object a {@code HomeserverRegistry} epoch commits to by hash.
 *
 * <p>Field order: schema tag; members as a list sorted by homeserverId, each {homeserverId, status,
 * memberEntryHash (optional), weight (int64), acceptsNew (bool), claims}. A claim is encoded as country,
 * mccmnc and carrier (each optional), phonePrefixes as a set, affiliation (optional), attributeMatch as a
 * count then its key/value pairs sorted by key, remoteClaimUrl (optional) and priority (int64).
 *
 * <p>Claims keep the order the content object carries, because that order is part of what the operator
 * signed and what the resolver rebuilds; members are sorted, because a membership set has no natural order
 * and a duplicate homeserver id would let one member be counted twice.
 */
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
