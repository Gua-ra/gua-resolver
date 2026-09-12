package global.gua.resolver.governance;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import global.gua.resolver.crypto.Ed25519;

/**
 * Shared governance test material. Every key is minted in memory for the test that uses it; nothing here
 * reads a key from a cluster, a secret or a file that ships.
 */
public final class GovernanceFixtures {

    private GovernanceFixtures() {}

    public static ObjectMapper mapper() {
        return new ObjectMapper().findAndRegisterModules()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /** A governance key plus the private half, so a test can sign as that operator. */
    public record Holder(GovernanceKey key, String privateKeyB64) {

        public static Holder of(String keyId, String operatorId) {
            Ed25519.KeyPairB64 pair = Ed25519.generate();
            return new Holder(new GovernanceKey(keyId, GovernanceKey.ALG, pair.publicKeyB64(), operatorId),
                    pair.privateKeyB64());
        }

        public GovernanceSignature sign(byte[] canonical) {
            return new GovernanceSignature(key.keyId(),
                    Ed25519.sign(Ed25519.privateKey(privateKeyB64), canonical));
        }
    }

    /** An unsigned genesis over the given holders' public keys. */
    public static FederationGenesis genesis(String label, long threshold, List<Holder> holders) {
        return new FederationGenesis(FederationGenesis.SCHEMA, label,
                Instant.parse("2026-09-01T00:00:00Z"), FederationGenesis.HASH_SUITE, threshold,
                holders.stream().map(Holder::key).toList(), Registry.allWireNames(), List.of());
    }

    /** The same genesis signed by each holder given. */
    public static FederationGenesis signed(FederationGenesis genesis, List<Holder> signers) {
        byte[] canonical = CanonicalGenesis.bytes(genesis);
        List<GovernanceSignature> signatures = new ArrayList<>();
        signers.forEach(h -> signatures.add(h.sign(canonical)));
        return genesis.withSignatures(signatures);
    }

    /** A single-operator genesis signed by its one key: what both environments actually deploy. */
    public static FederationGenesis singleOperator(String label, Holder holder) {
        return signed(genesis(label, 1, List.of(holder)), List.of(holder));
    }

    public static Path write(Path dir, String name, FederationGenesis genesis) throws Exception {
        Path file = dir.resolve(name);
        Files.writeString(file, mapper().writeValueAsString(genesis));
        return file;
    }

    /** A registry epoch signed by the given holders over its canonical bytes. */
    public static RegistryEpoch epoch(String genesisId, long number, String previousEpochHash,
                                      String contentHash, List<Holder> signers) {
        RegistryEpoch unsigned = new RegistryEpoch(RegistryEpoch.SCHEMA, Registry.HOMESERVERS, genesisId,
                number, previousEpochHash, Instant.now().truncatedTo(ChronoUnit.MILLIS), contentHash,
                List.of());
        byte[] canonical = CanonicalRegistryEpoch.bytes(unsigned);
        List<GovernanceSignature> signatures = new ArrayList<>();
        signers.forEach(h -> signatures.add(h.sign(canonical)));
        return unsigned.withSignatures(signatures);
    }
}
