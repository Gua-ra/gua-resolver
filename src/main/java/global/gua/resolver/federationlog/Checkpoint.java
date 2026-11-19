package global.gua.resolver.federationlog;

import java.time.Instant;
import java.util.List;

import global.gua.resolver.crypto.CanonicalEncoder;

/** A log size, root and state signed by the resolver. The signatures sit outside the canonical bytes. */
public record Checkpoint(
        String schema,
        String genesisId,
        long size,
        String rootHash,
        String stateHash,
        Instant lastLoggedAt,
        List<KeySignature> signatures) {

    public static final String SCHEMA = "gua-checkpoint.v1";

    public Checkpoint {
        signatures = signatures == null ? List.of() : List.copyOf(signatures);
    }

    public void validateShape() {
        if (!SCHEMA.equals(schema)) {
            throw new FederationLogException("unsupported checkpoint schema: " + schema);
        }
        Checks.sha256Hex(genesisId, "genesisId");
        if (size < 1) {
            throw new FederationLogException("a checkpoint covers at least the genesis entry");
        }
        Checks.sha256Hex(rootHash, "rootHash");
        Checks.sha256Hex(stateHash, "stateHash");
        Checks.millis(lastLoggedAt, "lastLoggedAt");
    }

    public byte[] canonicalBytes() {
        if (lastLoggedAt == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("lastLoggedAt is required");
        }
        return CanonicalEncoder.begin(SCHEMA)
                .string(genesisId)
                .int64(size)
                .string(rootHash)
                .string(stateHash)
                .int64(lastLoggedAt.toEpochMilli())
                .toByteArray();
    }

    /** What a witness signature names. */
    public String hash() {
        return CanonicalEncoder.sha256Hex(canonicalBytes());
    }
}
