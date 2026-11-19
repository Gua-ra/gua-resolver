package global.gua.resolver.federationlog;

import java.nio.file.Files;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.governance.CanonicalGenesis;
import global.gua.resolver.governance.CanonicalRegistryEpoch;
import global.gua.resolver.governance.CanonicalWitnessRegistryContent;
import global.gua.resolver.governance.CheckpointKey;
import global.gua.resolver.governance.FederationGenesis;
import global.gua.resolver.governance.GovernanceFixtures;
import global.gua.resolver.governance.GovernanceJson;
import global.gua.resolver.governance.RegistryEpoch;
import global.gua.resolver.governance.WitnessRegistryContent;

import static org.assertj.core.api.Assertions.assertThat;

class FederationLogVectorsTest {

    private static final ObjectMapper JSON = GovernanceFixtures.mapper();

    private static JsonNode vectors() throws Exception {
        return JSON.readTree(Files.readString(FederationLogVectorsGenerator.OUT));
    }

    private static <T> T read(JsonNode vector, Class<T> type) {
        return GovernanceJson.read(JSON, vector.get("object"), type);
    }

    private static String hex(byte[] bytes) {
        return CanonicalEncoder.hex(bytes);
    }

    @Test
    void everyLogEntryReproducesItsBytesAndLeafHashAndTheRoot() throws Exception {
        JsonNode log = vectors().get("log");
        List<String> leafHashes = new ArrayList<>();
        for (JsonNode vector : log.get("entries")) {
            LogEntry entry = read(vector, LogEntry.class);
            entry.validateShape();
            assertThat(entry.index()).isEqualTo(leafHashes.size());
            assertThat(hex(entry.canonicalBytes())).isEqualTo(vector.get("canonicalHex").asText());
            assertThat(entry.leafHash()).isEqualTo(vector.get("leafHash").asText());
            leafHashes.add(entry.leafHash());
        }
        assertThat(MerkleTree.root(leafHashes)).isEqualTo(log.get("rootHash").asText());
    }

    @Test
    void theEntriesNameTheSignedGenesisAndWitnessListEpoch() throws Exception {
        JsonNode root = vectors();
        FederationGenesis genesis = read(root.get("genesis"), FederationGenesis.class);
        genesis.validateShape();
        RegistryEpoch epoch = read(root.get("witnessListEpoch"), RegistryEpoch.class);
        epoch.validateShape();
        assertThat(hex(CanonicalRegistryEpoch.bytes(epoch)))
                .isEqualTo(root.get("witnessListEpoch").get("canonicalHex").asText());
        assertThat(CanonicalRegistryEpoch.hash(epoch))
                .isEqualTo(root.get("witnessListEpoch").get("sha256Hex").asText());

        PublicKey governanceKey = Ed25519.publicKey(genesis.keys().getFirst().publicKey());
        assertThat(Ed25519.verify(governanceKey, CanonicalGenesis.bytes(genesis),
                genesis.signatures().getFirst().signatureB64())).isTrue();
        assertThat(Ed25519.verify(governanceKey, CanonicalRegistryEpoch.bytes(epoch),
                epoch.signatures().getFirst().signatureB64())).isTrue();

        JsonNode entries = root.get("log").get("entries");
        LogEntry genesisEntry = read(entries.get(0), LogEntry.class);
        LogEntry epochEntry = read(entries.get(1), LogEntry.class);
        assertThat(genesisEntry.objectHash()).isEqualTo(CanonicalGenesis.id(genesis))
                .isEqualTo(root.get("genesis").get("genesisId").asText());
        assertThat(genesisEntry.signatures()).containsExactly(
                new KeySignature("gov-1", genesis.signatures().getFirst().signatureB64()));
        assertThat(epochEntry.objectHash()).isEqualTo(CanonicalRegistryEpoch.hash(epoch));
        assertThat(epochEntry.signatures()).containsExactly(
                new KeySignature("gov-1", epoch.signatures().getFirst().signatureB64()));
        assertThat(epoch.contentHash()).isEqualTo(CanonicalWitnessRegistryContent.hash(
                read(root.get("witnessLists").get(1), WitnessRegistryContent.class)));
    }

    @Test
    void everyWitnessListReproduces() throws Exception {
        for (JsonNode vector : vectors().get("witnessLists")) {
            WitnessRegistryContent list = read(vector, WitnessRegistryContent.class);
            list.validateShape();
            assertThat(hex(CanonicalWitnessRegistryContent.bytes(list)))
                    .isEqualTo(vector.get("canonicalHex").asText());
            assertThat(CanonicalWitnessRegistryContent.hash(list)).isEqualTo(vector.get("sha256Hex").asText());
        }
    }

    @Test
    void theStateAndCheckpointFollowFromTheLog() throws Exception {
        JsonNode root = vectors();
        FederationState state = read(root.get("state"), FederationState.class);
        state.validateShape();
        assertThat(hex(state.canonicalBytes())).isEqualTo(root.get("state").get("canonicalHex").asText());
        assertThat(state.hash()).isEqualTo(root.get("state").get("sha256Hex").asText());
        assertThat(state.witnessEpochHash()).isEqualTo(root.get("witnessListEpoch").get("sha256Hex").asText());

        Checkpoint checkpoint = read(root.get("checkpoint"), Checkpoint.class);
        checkpoint.validateShape();
        assertThat(hex(checkpoint.canonicalBytes())).isEqualTo(root.get("checkpoint").get("canonicalHex").asText());
        assertThat(checkpoint.hash()).isEqualTo(root.get("checkpoint").get("sha256Hex").asText());

        JsonNode entries = root.get("log").get("entries");
        assertThat(checkpoint.size()).isEqualTo(entries.size());
        assertThat(checkpoint.rootHash()).isEqualTo(root.get("log").get("rootHash").asText());
        assertThat(checkpoint.stateHash()).isEqualTo(state.hash());
        assertThat(checkpoint.lastLoggedAt()).isEqualTo(read(entries.get(entries.size() - 1), LogEntry.class)
                .loggedAt());
    }

    @Test
    void homeserverEntriesInTheStateEncodeInHomeserverIdOrder() throws Exception {
        JsonNode vector = vectors().get("stateWithMembers");
        FederationState state = read(vector, FederationState.class);
        state.validateShape();
        assertThat(hex(state.canonicalBytes())).isEqualTo(vector.get("canonicalHex").asText());
        assertThat(state.hash()).isEqualTo(vector.get("sha256Hex").asText());
        FederationState reordered = new FederationState(state.schema(), state.genesisId(),
                state.governanceChainHead(), state.homeserverEpochHash(), state.memberEntries().reversed(),
                state.witnessEpochHash());
        assertThat(reordered.canonicalBytes()).isEqualTo(state.canonicalBytes());
    }

    @Test
    void theCheckpointAndWitnessSignaturesVerifyUnderTheListedKeys() throws Exception {
        JsonNode root = vectors();
        WitnessRegistryContent list = read(root.get("witnessLists").get(1), WitnessRegistryContent.class);
        Checkpoint checkpoint = read(root.get("checkpoint"), Checkpoint.class);
        WitnessSignature witness = read(root.get("witnessSignature"), WitnessSignature.class);
        witness.validateShape();
        assertThat(hex(witness.canonicalBytes())).isEqualTo(root.get("witnessSignature").get("canonicalHex").asText());
        assertThat(witness.checkpointHash()).isEqualTo(checkpoint.hash());

        KeySignature resolverSignature = checkpoint.signatures().getFirst();
        assertThat(Ed25519.verify(publicKey(list, resolverSignature.keyId(), CheckpointKey.Role.RESOLVER),
                checkpoint.canonicalBytes(), resolverSignature.signatureB64())).isTrue();
        assertThat(Ed25519.verify(publicKey(list, witness.keyId(), CheckpointKey.Role.WITNESS),
                witness.canonicalBytes(), witness.signatureB64())).isTrue();
    }

    @Test
    void entrySignaturesEncodeInKeyIdOrder() throws Exception {
        JsonNode vector = vectors().get("memberEntryKeyChange");
        LogEntry entry = read(vector, LogEntry.class);
        entry.validateShape();
        LogEntry reversed = new LogEntry(entry.schema(), entry.genesisId(), entry.index(), entry.loggedAt(),
                entry.type(), entry.objectHash(), entry.signatures().reversed());
        assertThat(hex(entry.canonicalBytes())).isEqualTo(vector.get("canonicalHex").asText());
        assertThat(reversed.canonicalBytes()).isEqualTo(entry.canonicalBytes());
    }

    private static PublicKey publicKey(WitnessRegistryContent list, String keyId, CheckpointKey.Role role) {
        return list.keys().stream()
                .filter(k -> k.keyId().equals(keyId) && k.role() == role)
                .map(k -> Ed25519.publicKey(k.publicKey()))
                .findFirst()
                .orElseThrow();
    }
}
