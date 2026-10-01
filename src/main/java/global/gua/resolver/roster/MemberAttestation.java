package global.gua.resolver.roster;

import java.time.Instant;
import java.util.List;

/** signatures are outside the signed bytes; a rotation carries one by the new key and one by the previous. */
public record MemberAttestation(
        String schema,
        String alg,
        String keyId,
        long sequence,
        Instant notBefore,
        Instant notAfter,
        List<MemberSignature> signatures) {

    public MemberAttestation {
        signatures = signatures == null ? List.of() : List.copyOf(signatures);
    }

    public MemberAttestation withSignatures(List<MemberSignature> newSignatures) {
        return new MemberAttestation(schema, alg, keyId, sequence, notBefore, notAfter, newSignatures);
    }
}
