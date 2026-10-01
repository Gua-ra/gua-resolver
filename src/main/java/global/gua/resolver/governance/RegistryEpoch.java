package global.gua.resolver.governance;

import java.time.Instant;
import java.util.List;

/** previousEpochHash is the empty string at epoch 1. */
public record RegistryEpoch(
        String schema,
        Registry registry,
        String genesisId,
        long epoch,
        String previousEpochHash,
        Instant issuedAt,
        String contentHash,
        List<GovernanceSignature> signatures) {

    public static final String SCHEMA = "gua-registry-epoch.v1";

    public RegistryEpoch {
        signatures = signatures == null ? List.of() : List.copyOf(signatures);
    }

    public RegistryEpoch withSignatures(List<GovernanceSignature> newSignatures) {
        return new RegistryEpoch(schema, registry, genesisId, epoch, previousEpochHash, issuedAt,
                contentHash, newSignatures);
    }

    public void validateShape() {
        if (!SCHEMA.equals(schema)) {
            throw new GovernanceException("unsupported epoch schema: " + schema);
        }
        if (registry == null) {
            throw new GovernanceException("registry is required");
        }
        if (genesisId == null || genesisId.isBlank()) {
            throw new GovernanceException("genesisId is required");
        }
        if (epoch < 1) {
            throw new GovernanceException("epoch starts at 1");
        }
        if (previousEpochHash == null) {
            throw new GovernanceException("previousEpochHash is required (empty at epoch 1)");
        }
        if (epoch == 1 && !previousEpochHash.isEmpty()) {
            throw new GovernanceException("epoch 1 has no previous epoch, so previousEpochHash is empty");
        }
        if (epoch > 1 && previousEpochHash.isEmpty()) {
            throw new GovernanceException("epoch " + epoch + " must name the previous epoch's hash");
        }
        if (issuedAt == null || issuedAt.getNano() % 1_000_000 != 0) {
            throw new GovernanceException("issuedAt is required at millisecond precision");
        }
        if (contentHash == null || contentHash.isBlank()) {
            throw new GovernanceException("contentHash is required");
        }
    }
}
