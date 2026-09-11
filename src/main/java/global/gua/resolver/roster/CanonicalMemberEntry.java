package global.gua.resolver.roster;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.domain.Homeserver;

/**
 * The {@code gua-member-entry.v1} canonical bytes: what a homeserver's member key signs about itself
 * (ADM-007). Encoded with {@code gua-lp.v1}, never with {@link CanonicalRoster}'s delimiter form (ADM-001 L4).
 *
 * <p>Field order: schema tag; homeserverId; serverName; baseUrl; masIssuer; alg; signingKey (base64 X.509
 * SubjectPublicKeyInfo, exactly as stored); keyId; sequence (int64); notBefore (int64 epoch ms); notAfter
 * (int64 epoch ms); region (optional string); searchVisibility (enum name); searchGroups (set of strings).
 *
 * <p>Not covered, because they are placement or governance attributes the authority still signs in the
 * roster: weight, acceptsNew, claims, admittedAt, status.
 */
public final class CanonicalMemberEntry {

    public static final String SCHEMA = "gua-member-entry.v1";
    public static final String ALG = "Ed25519";

    private CanonicalMemberEntry() {}

    /**
     * Canonical bytes for {@code homeserver} as attested by {@code member}; signatures are excluded.
     *
     * @throws CanonicalEncoder.CanonicalEncodingException when a field has no canonical encoding (a missing
     *         required value, a duplicate search group, an invalid string); such an entry must be refused
     */
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

    /** SHA-256 hex of {@link #bytes}: the payload of the {@code MEMBER_ATTEST} log leaf. */
    public static String hash(Homeserver homeserver, MemberAttestation member) {
        return CanonicalEncoder.sha256Hex(bytes(homeserver, member));
    }
}
