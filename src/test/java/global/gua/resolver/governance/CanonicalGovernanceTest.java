package global.gua.resolver.governance;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.Rfc8032Keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The published governance vectors (docs/specs/gua-governance-v1-vectors.json) are the contract the iOS and
 * Android ports check themselves against, so they are recomputed here byte for byte: canonical bytes, object
 * hashes and deterministic Ed25519 signatures for the genesis, the key transition, the registry epoch and the
 * homeserver registry content.
 */
class CanonicalGovernanceTest {

    private static final Path VECTORS = Path.of("docs/specs/gua-governance-v1-vectors.json");
    private static final ObjectMapper JSON = GovernanceFixtures.mapper();

    private static JsonNode vectors() throws Exception {
        return JSON.readTree(Files.readString(VECTORS));
    }

    private static Ed25519.KeyPairB64 key(JsonNode root, String ref) {
        JsonNode k = root.get("keys").get(ref);
        return Rfc8032Keys.pair(k.get("seedHex").asText(), k.get("publicKeyHex").asText());
    }

    /** Recompute the bytes, the hash and every published signature for one vector. */
    private static void check(JsonNode root, JsonNode vector, byte[] canonical) {
        String name = vector.get("name").asText();
        assertThat(CanonicalEncoder.hex(canonical)).as(name).isEqualTo(vector.get("canonicalHex").asText());
        assertThat(CanonicalEncoder.sha256Hex(canonical)).as(name)
                .isEqualTo(vector.get("sha256Hex").asText());

        for (JsonNode signature : vector.path("signatures")) {
            Ed25519.KeyPairB64 pair = key(root, signature.get("keyRef").asText());
            // Ed25519 is deterministic: re-signing the same bytes reproduces the published signature.
            assertThat(Ed25519.sign(Ed25519.privateKey(pair.privateKeyB64()), canonical))
                    .as("%s / %s", name, signature.get("keyId").asText())
                    .isEqualTo(signature.get("signatureB64").asText());
            assertThat(Ed25519.verify(Ed25519.publicKey(pair.publicKeyB64()), canonical,
                    signature.get("signatureB64").asText())).isTrue();
        }
    }

    @Test
    void everyGenesisVectorReproducesItsBytesIdAndSignatures() throws Exception {
        JsonNode root = vectors();
        assertThat(root.get("encoding").asText()).isEqualTo(CanonicalEncoder.ENCODING);

        for (JsonNode vector : root.get("genesis")) {
            FederationGenesis genesis =
                    GovernanceJson.read(JSON, vector.get("object"), FederationGenesis.class);
            genesis.validateShape();
            byte[] canonical = CanonicalGenesis.bytes(genesis);
            check(root, vector, canonical);
            assertThat(CanonicalGenesis.id(genesis)).isEqualTo(vector.get("genesisId").asText());
            assertThat(CanonicalGenesis.fingerprint(CanonicalGenesis.id(genesis)))
                    .isEqualTo(vector.get("fingerprint").asText());
        }
    }

    @Test
    void listingTheSameKeySetInADifferentOrderYieldsTheSameBytes() throws Exception {
        JsonNode root = vectors();
        JsonNode reversed = null;
        String twin = null;
        for (JsonNode vector : root.get("genesis")) {
            if (vector.hasNonNull("sameBytesAs")) {
                reversed = vector;
                twin = vector.get("sameBytesAs").asText();
            }
        }
        assertThat(reversed).as("a reversed-order genesis vector is published").isNotNull();

        String twinHash = null;
        for (JsonNode vector : root.get("genesis")) {
            FederationGenesis g = GovernanceJson.read(JSON, vector.get("object"), FederationGenesis.class);
            if (g.federationLabel().equals(twin) && vector != reversed) {
                twinHash = vector.get("sha256Hex").asText();
            }
        }
        assertThat(reversed.get("sha256Hex").asText()).isEqualTo(twinHash);
    }

    @Test
    void everyTransitionVectorReproduces() throws Exception {
        JsonNode root = vectors();
        for (JsonNode vector : root.get("transitions")) {
            GovernanceTransition transition =
                    GovernanceJson.read(JSON, vector.get("object"), GovernanceTransition.class);
            transition.validateShape();
            check(root, vector, CanonicalGovernanceTransition.bytes(transition));
            assertThat(CanonicalGovernanceTransition.hash(transition))
                    .isEqualTo(vector.get("sha256Hex").asText());
        }
    }

    @Test
    void everyRegistryEpochVectorReproduces() throws Exception {
        JsonNode root = vectors();
        for (JsonNode vector : root.get("registryEpochs")) {
            RegistryEpoch epoch = GovernanceJson.read(JSON, vector.get("object"), RegistryEpoch.class);
            epoch.validateShape();
            check(root, vector, CanonicalRegistryEpoch.bytes(epoch));
            assertThat(CanonicalRegistryEpoch.hash(epoch)).isEqualTo(vector.get("sha256Hex").asText());
        }
    }

    @Test
    void everyRegistryContentVectorReproduces() throws Exception {
        JsonNode root = vectors();
        for (JsonNode vector : root.get("registryContents")) {
            HomeserverRegistryContent content =
                    GovernanceJson.read(JSON, vector.get("object"), HomeserverRegistryContent.class);
            content.validateShape();
            check(root, vector, CanonicalHomeserverRegistryContent.bytes(content));
        }
    }

    @Test
    void aDuplicateKeyIdAndADuplicateMemberHaveNoCanonicalEncoding() {
        FederationGenesis duplicateKey = new FederationGenesis(FederationGenesis.SCHEMA, "dup",
                java.time.Instant.parse("2026-09-01T00:00:00Z"), FederationGenesis.HASH_SUITE, 1,
                List.of(new GovernanceKey("gov-1", GovernanceKey.ALG, Rfc8032Keys.test1().publicKeyB64(),
                                "operator-a"),
                        new GovernanceKey("gov-1", GovernanceKey.ALG, Rfc8032Keys.test2().publicKeyB64(),
                                "operator-b")),
                Registry.allWireNames(), List.of());

        assertThatThrownBy(() -> CanonicalGenesis.bytes(duplicateKey))
                .isInstanceOf(CanonicalEncoder.CanonicalEncodingException.class)
                .hasMessageContaining("duplicate governance key id");

        HomeserverRegistryContent duplicateMember = HomeserverRegistryContent.of(List.of(
                new RegistryMember("hs1", global.gua.resolver.roster.RosterEntry.Status.ACTIVE, null, 1,
                        true, List.of()),
                new RegistryMember("hs1", global.gua.resolver.roster.RosterEntry.Status.REVOKED, null, 1,
                        true, List.of())));

        assertThatThrownBy(() -> CanonicalHomeserverRegistryContent.bytes(duplicateMember))
                .isInstanceOf(CanonicalEncoder.CanonicalEncodingException.class)
                .hasMessageContaining("duplicate registry member");
    }

    @Test
    void theStrictTransportParseRefusesAnUnknownFieldInASignedObject() throws Exception {
        JsonNode object = vectors().get("genesis").get(0).get("object").deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) object).put("threshold2", 99);

        assertThatThrownBy(() -> GovernanceJson.read(JSON, object, FederationGenesis.class))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("does not parse strictly");
    }
}
