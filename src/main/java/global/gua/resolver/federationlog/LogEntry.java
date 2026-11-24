package global.gua.resolver.federationlog;

import java.time.Instant;
import java.util.List;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.governance.CanonicalOrder;

/** One federation log entry. The object it names travels beside it and must hash to {@code objectHash}. */
public record LogEntry(
        String schema,
        String genesisId,
        long index,
        Instant loggedAt,
        Type type,
        String objectHash,
        List<KeySignature> signatures) {

    public static final String SCHEMA = "gua-log-entry.v1";

    public enum Type {
        GENESIS,
        GOVERNANCE_TRANSITION,
        REGISTRY_EPOCH,
        MEMBER_ENTRY,
        TIME
    }

    public LogEntry {
        signatures = signatures == null ? List.of() : List.copyOf(signatures);
    }

    public void validateShape() {
        if (!SCHEMA.equals(schema)) {
            throw new FederationLogException("unsupported entry schema: " + schema);
        }
        Checks.sha256Hex(genesisId, "genesisId");
        if (index < 0) {
            throw new FederationLogException("index starts at 0");
        }
        Checks.millis(loggedAt, "loggedAt");
        if (type == null) {
            throw new FederationLogException("type is required");
        }
        if (type == Type.TIME) {
            if (objectHash != null || !signatures.isEmpty()) {
                throw new FederationLogException("a time entry names no object and carries no signatures");
            }
        } else {
            Checks.sha256Hex(objectHash, "objectHash");
            if (signatures.isEmpty()) {
                throw new FederationLogException("a logged object must be signed");
            }
        }
        if ((type == Type.GENESIS) != (index == 0)) {
            throw new FederationLogException("entry 0 is the genesis, and no other entry is");
        }
        if (type == Type.GENESIS && !genesisId.equals(objectHash)) {
            throw new FederationLogException("the genesis entry names the genesis itself");
        }
    }

    public byte[] canonicalBytes() {
        if (loggedAt == null || type == null) {
            throw new CanonicalEncoder.CanonicalEncodingException("loggedAt and type are required");
        }
        List<KeySignature> sorted =
                CanonicalOrder.sortedUnique(signatures, KeySignature::keyId, "signature key id");
        CanonicalEncoder e = CanonicalEncoder.begin(SCHEMA)
                .string(genesisId)
                .int64(index)
                .int64(loggedAt.toEpochMilli())
                .enumName(type)
                .optionalString(objectHash)
                .listCount(sorted.size());
        for (KeySignature signature : sorted) {
            e.string(signature.keyId()).bytes(Checks.signatureBytes(signature.signatureB64()));
        }
        return e.toByteArray();
    }

    /** The RFC 6962 leaf hash of the canonical bytes, which the log's Merkle tree is built from. */
    public String leafHash() {
        return MerkleTree.leafHash(canonicalBytes());
    }
}
