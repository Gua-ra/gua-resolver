package global.gua.resolver.roster;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.domain.Homeserver;

/** The bytes a member key signs. weight, acceptsNew, claims, admittedAt and status are not covered. */
public final class CanonicalMemberEntry {

    public static final String SCHEMA = "gua-member-entry.v1";
    public static final String ALG = "Ed25519";

    private CanonicalMemberEntry() {}

    public static byte[] bytes(Homeserver homeserver, MemberAttestation member) {
        if (homeserver == null || member == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("homeserver and member are required");
        }
        if (member.notBefore() == null || member.notAfter() == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("notBefore and notAfter are required");
        }
        return CanonicalEncoder.begin(SCHEMA)
                .string(homeserver.id())
                .string(homeserver.serverName())
                .string(homeserver.baseUrl())
                .string(homeserver.masIssuer())
                .string(member.alg())
                .string(homeserver.signingKey())
                .string(member.keyId())
                .int64(member.sequence())
                .int64(member.notBefore().toEpochMilli())
                .int64(member.notAfter().toEpochMilli())
                .optionalString(homeserver.region())
                .enumName(homeserver.searchVisibility())
                .stringSet(homeserver.searchGroups())
                .toByteArray();
    }

    public static String hash(Homeserver homeserver, MemberAttestation member) {
        return CanonicalEncoder.sha256Hex(bytes(homeserver, member));
    }
}
