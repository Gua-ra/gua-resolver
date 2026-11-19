package global.gua.resolver.federationlog;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.crypto.Rfc8032Keys;
import global.gua.resolver.governance.CanonicalGenesis;
import global.gua.resolver.governance.CanonicalRegistryEpoch;
import global.gua.resolver.governance.CanonicalWitnessRegistryContent;
import global.gua.resolver.governance.CheckpointKey;
import global.gua.resolver.governance.FederationGenesis;
import global.gua.resolver.governance.GovernanceFixtures;
import global.gua.resolver.governance.GovernanceKey;
import global.gua.resolver.governance.GovernanceSignature;
import global.gua.resolver.governance.Registry;
import global.gua.resolver.governance.RegistryEpoch;
import global.gua.resolver.governance.WitnessRegistryContent;

/**
 * Regenerates docs/specs/gua-federation-log-v1-vectors.json with {@code ./gradlew federationLogVectors}.
 * FederationLogVectorsTest reproduces every value, so a diff in that file changes a published wire contract.
 */
public final class FederationLogVectorsGenerator {

    static final Path OUT = Path.of("docs/specs/gua-federation-log-v1-vectors.json");

    private static final ObjectMapper JSON = GovernanceFixtures.mapper();
    private static final Ed25519.KeyPairB64 GOVERNANCE = Rfc8032Keys.test1();
    private static final Ed25519.KeyPairB64 RESOLVER = Rfc8032Keys.test2();
    private static final Ed25519.KeyPairB64 WITNESS = Rfc8032Keys.test3();

    private FederationLogVectorsGenerator() {}

    public static void main(String[] args) throws Exception {
        Files.writeString(OUT, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(vectors()) + "\n");
        System.out.println("wrote " + OUT);
    }

    private static ObjectNode vectors() {
        ObjectNode root = JSON.createObjectNode();
        root.put("encoding", CanonicalEncoder.ENCODING);
        root.put("spec", "docs/specs/federation-log.md");
        ArrayNode notes = root.putArray("notes");
        notes.add("Keys are the RFC 8032 section 7.1 TEST 1, 2 and 3 Ed25519 keys, published test constants that "
                + "must never sign anything real.");
        notes.add("Timestamps travel as ISO-8601 UTC at millisecond precision. Canonical bytes carry epoch "
                + "milliseconds, so the vectors use values ending in .001 and .999.");
        notes.add("Entry signatures travel as base64 and are encoded as their raw 64 bytes. Lists sorted by an "
                + "id use unsigned UTF-8 byte order.");
        notes.add("A conforming implementation reproduces every canonicalHex, sha256Hex, leafHash and rootHash, "
                + "and verifies every signature except the placeholders in memberEntryKeyChange.");
        ObjectNode keys = root.putObject("keys");
        key(keys, "rfc8032-test1", "governance key gov-1", Rfc8032Keys.TEST1_SEED_HEX,
                Rfc8032Keys.TEST1_PUBLIC_HEX, GOVERNANCE);
        key(keys, "rfc8032-test2", "resolver checkpoint key resolver-1", Rfc8032Keys.TEST2_SEED_HEX,
                Rfc8032Keys.TEST2_PUBLIC_HEX, RESOLVER);
        key(keys, "rfc8032-test3", "witness key witness-1", Rfc8032Keys.TEST3_SEED_HEX,
                Rfc8032Keys.TEST3_PUBLIC_HEX, WITNESS);

        FederationGenesis unsignedGenesis = new FederationGenesis(FederationGenesis.SCHEMA, "gua-vectors",
                Instant.parse("2026-11-01T00:00:00Z"), FederationGenesis.HASH_SUITE, 1,
                List.of(new GovernanceKey("gov-1", GovernanceKey.ALG, GOVERNANCE.publicKeyB64(), "operator-a")),
                Registry.allWireNames(), List.of());
        FederationGenesis genesis = unsignedGenesis.withSignatures(List.of(
                new GovernanceSignature("gov-1", sign(GOVERNANCE, CanonicalGenesis.bytes(unsignedGenesis)))));
        String genesisId = CanonicalGenesis.id(genesis);
        ObjectNode genesisNode = root.putObject("genesis");
        genesisNode.set("object", JSON.valueToTree(genesis));
        genesisNode.put("genesisId", genesisId);

        CheckpointKey resolverKey = new CheckpointKey("resolver-1", GovernanceKey.ALG, RESOLVER.publicKeyB64(),
                "operator-a", CheckpointKey.Role.RESOLVER, "https://resolver.example.test");
        CheckpointKey witnessKey = new CheckpointKey("witness-1", GovernanceKey.ALG, WITNESS.publicKeyB64(),
                "operator-b", CheckpointKey.Role.WITNESS, "https://witness.example.test");
        WitnessRegistryContent resolverOnly =
                new WitnessRegistryContent(WitnessRegistryContent.SCHEMA, 0, List.of(resolverKey));
        WitnessRegistryContent witnessed =
                new WitnessRegistryContent(WitnessRegistryContent.SCHEMA, 1, List.of(witnessKey, resolverKey));
        ArrayNode lists = root.putArray("witnessLists");
        lists.add(witnessListVector("the resolver key alone, so nothing is witnessed yet", resolverOnly));
        lists.add(witnessListVector("one witness from another operator, required 1, keys listed out of order",
                witnessed));

        RegistryEpoch unsignedEpoch = new RegistryEpoch(RegistryEpoch.SCHEMA, Registry.WITNESSES, genesisId, 1,
                "", Instant.parse("2026-11-01T00:01:00.999Z"), CanonicalWitnessRegistryContent.hash(witnessed),
                List.of());
        RegistryEpoch epoch = unsignedEpoch.withSignatures(List.of(
                new GovernanceSignature("gov-1", sign(GOVERNANCE, CanonicalRegistryEpoch.bytes(unsignedEpoch)))));
        String epochHash = CanonicalRegistryEpoch.hash(epoch);
        ObjectNode epochNode = root.putObject("witnessListEpoch");
        epochNode.set("object", JSON.valueToTree(epoch));
        epochNode.put("canonicalHex", CanonicalEncoder.hex(CanonicalRegistryEpoch.bytes(epoch)));
        epochNode.put("sha256Hex", epochHash);

        List<LogEntry> entries = List.of(
                new LogEntry(LogEntry.SCHEMA, genesisId, 0, Instant.parse("2026-11-01T00:00:05.001Z"),
                        LogEntry.Type.GENESIS, genesisId, keySignatures(genesis.signatures())),
                new LogEntry(LogEntry.SCHEMA, genesisId, 1, Instant.parse("2026-11-01T00:01:05.999Z"),
                        LogEntry.Type.REGISTRY_EPOCH, epochHash, keySignatures(epoch.signatures())),
                new LogEntry(LogEntry.SCHEMA, genesisId, 2, Instant.parse("2026-11-01T00:02:05.500Z"),
                        LogEntry.Type.TIME, null, List.of()));
        ObjectNode log = root.putObject("log");
        ArrayNode entryNodes = log.putArray("entries");
        entries.forEach(entry -> entryNodes.add(entryVector(entry)));
        String rootHash = MerkleTree.root(entries.stream().map(LogEntry::leafHash).toList());
        log.put("rootHash", rootHash);

        FederationState state =
                new FederationState(FederationState.SCHEMA, genesisId, genesisId, null, List.of(), epochHash);
        root.set("state", stateVector(
                "the state of the log above: no membership epoch and no homeserver entries", state));

        FederationState withMembers = new FederationState(FederationState.SCHEMA, genesisId,
                CanonicalEncoder.sha256Hex("example key change".getBytes(StandardCharsets.UTF_8)),
                CanonicalEncoder.sha256Hex("example membership epoch".getBytes(StandardCharsets.UTF_8)),
                List.of(new FederationState.MemberEntry("hs2",
                                CanonicalEncoder.sha256Hex("hs2 entry".getBytes(StandardCharsets.UTF_8))),
                        new FederationState.MemberEntry("hs1",
                                CanonicalEncoder.sha256Hex("hs1 entry".getBytes(StandardCharsets.UTF_8)))),
                epochHash);
        root.set("stateWithMembers", stateVector(
                "after a key change and a membership epoch, homeserver entries listed out of order", withMembers));

        Checkpoint unsignedCheckpoint = new Checkpoint(Checkpoint.SCHEMA, genesisId, entries.size(), rootHash,
                state.hash(), entries.getLast().loggedAt(), List.of());
        Checkpoint checkpoint = new Checkpoint(Checkpoint.SCHEMA, genesisId, entries.size(), rootHash,
                state.hash(), entries.getLast().loggedAt(),
                List.of(new KeySignature("resolver-1", sign(RESOLVER, unsignedCheckpoint.canonicalBytes()))));
        ObjectNode checkpointNode = root.putObject("checkpoint");
        checkpointNode.set("object", JSON.valueToTree(checkpoint));
        checkpointNode.put("canonicalHex", CanonicalEncoder.hex(checkpoint.canonicalBytes()));
        checkpointNode.put("sha256Hex", checkpoint.hash());

        WitnessSignature unsignedWitness = new WitnessSignature(WitnessSignature.SCHEMA, checkpoint.hash(),
                "witness-1", Instant.parse("2026-11-01T00:02:30.123Z"), null);
        WitnessSignature witnessSignature = new WitnessSignature(WitnessSignature.SCHEMA, checkpoint.hash(),
                "witness-1", unsignedWitness.signedAt(), sign(WITNESS, unsignedWitness.canonicalBytes()));
        ObjectNode witnessNode = root.putObject("witnessSignature");
        witnessNode.set("object", JSON.valueToTree(witnessSignature));
        witnessNode.put("canonicalHex", CanonicalEncoder.hex(witnessSignature.canonicalBytes()));

        String memberEntryHash =
                CanonicalEncoder.sha256Hex("example member entry".getBytes(StandardCharsets.UTF_8));
        LogEntry keyChange = new LogEntry(LogEntry.SCHEMA, genesisId, 7,
                Instant.parse("2026-11-01T00:09:00.001Z"), LogEntry.Type.MEMBER_ENTRY, memberEntryHash, List.of(
                        new KeySignature("hs1-key-2", placeholderSignature(2)),
                        new KeySignature("hs1-key-1", placeholderSignature(1))));
        ObjectNode keyChangeNode = entryVector(keyChange);
        keyChangeNode.put("name", "a homeserver key change: two signatures listed out of order encode sorted "
                + "by keyId. The signatures are placeholders, so this vector pins encoding only");
        root.set("memberEntryKeyChange", keyChangeNode);
        return root;
    }

    private static ObjectNode witnessListVector(String name, WitnessRegistryContent content) {
        ObjectNode vector = JSON.createObjectNode();
        vector.put("name", name);
        vector.set("object", JSON.valueToTree(content));
        vector.put("canonicalHex", CanonicalEncoder.hex(CanonicalWitnessRegistryContent.bytes(content)));
        vector.put("sha256Hex", CanonicalWitnessRegistryContent.hash(content));
        return vector;
    }

    private static ObjectNode stateVector(String name, FederationState state) {
        ObjectNode vector = JSON.createObjectNode();
        vector.put("name", name);
        vector.set("object", JSON.valueToTree(state));
        vector.put("canonicalHex", CanonicalEncoder.hex(state.canonicalBytes()));
        vector.put("sha256Hex", state.hash());
        return vector;
    }

    private static ObjectNode entryVector(LogEntry entry) {
        ObjectNode vector = JSON.createObjectNode();
        vector.set("object", JSON.valueToTree(entry));
        vector.put("canonicalHex", CanonicalEncoder.hex(entry.canonicalBytes()));
        vector.put("leafHash", entry.leafHash());
        return vector;
    }

    private static List<KeySignature> keySignatures(List<GovernanceSignature> signatures) {
        return signatures.stream().map(s -> new KeySignature(s.keyId(), s.signatureB64())).toList();
    }

    private static String sign(Ed25519.KeyPairB64 pair, byte[] message) {
        return Ed25519.sign(Ed25519.privateKey(pair.privateKeyB64()), message);
    }

    private static String placeholderSignature(int fill) {
        byte[] bytes = new byte[64];
        Arrays.fill(bytes, (byte) fill);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static void key(ObjectNode keys, String ref, String usedAs, String seedHex, String publicHex,
                            Ed25519.KeyPairB64 pair) {
        ObjectNode node = keys.putObject(ref);
        node.put("usedAs", usedAs);
        node.put("seedHex", seedHex);
        node.put("publicKeyHex", publicHex);
        node.put("publicKeySpkiB64", pair.publicKeyB64());
        node.put("privateKeyPkcs8B64", pair.privateKeyB64());
    }
}
