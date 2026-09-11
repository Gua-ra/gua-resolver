package global.gua.resolver.roster;

import java.time.Instant;
import java.util.List;

/**
 * The member-controlled half of a self-signed roster entry (ADM-007). The endpoint and key fields it signs
 * stay where clients already read them, in {@code RosterEntry.homeserver}; this block carries the attestation
 * metadata and the signatures. {@link CanonicalMemberEntry} defines the signed bytes. {@code signatures} are
 * outside them: a key rotation carries one signature by the new key and one by the previous key over the
 * same bytes.
 *
 * @param schema     {@link CanonicalMemberEntry#SCHEMA}
 * @param alg        {@link CanonicalMemberEntry#ALG}
 * @param keyId      label of {@code homeserver.signingKey}; names exactly one key
 * @param sequence   starts at 1, strictly increasing per homeserver id
 * @param notBefore  start of validity, millisecond precision
 * @param notAfter   end of validity, after {@code notBefore}, lifetime capped by configuration
 * @param signatures detached signatures over the canonical bytes
 */
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

    /** The same attestation with a different signature list. */
    public MemberAttestation withSignatures(List<MemberSignature> newSignatures) {
        return new MemberAttestation(schema, alg, keyId, sequence, notBefore, notAfter, newSignatures);
    }
}
