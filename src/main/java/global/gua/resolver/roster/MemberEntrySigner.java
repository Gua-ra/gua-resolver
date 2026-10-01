package global.gua.resolver.roster;

import java.util.ArrayList;
import java.util.List;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;

public final class MemberEntrySigner {

    private MemberEntrySigner() {}

    /** For a rotation call it twice: once with the new key, and once with the previous key and its id. */
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
