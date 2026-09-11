package global.gua.resolver.roster;

import java.util.ArrayList;
import java.util.List;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;

/**
 * Signs a member entry's canonical bytes. Used by tests and the offline {@code MemberEntryTool}; the resolver
 * never holds a member private key.
 */
public final class MemberEntrySigner {

    private MemberEntrySigner() {}

    /**
     * Add (or replace) the signature for {@code keyId} over the {@code gua-member-entry.v1} bytes of
     * {@code homeserver} + {@code member}. For a rotation call it twice on the same entry: once with the new
     * key (whose id is {@code member.keyId()}) and once with the previous key and its id.
     */
    public static MemberAttestation sign(Homeserver homeserver, MemberAttestation member, String keyId,
                                         String privateKeyB64) {
        byte[] canonical = CanonicalMemberEntry.bytes(homeserver, member);
        MemberSignature signature = new MemberSignature(keyId,
                Ed25519.sign(Ed25519.privateKey(privateKeyB64), canonical));
        List<MemberSignature> signatures = new ArrayList<>(member.signatures());
        signatures.removeIf(s -> keyId.equals(s.keyId()));
        signatures.add(signature);
        return member.withSignatures(signatures);
    }
}
