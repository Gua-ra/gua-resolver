package global.gua.resolver.governance;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.Rfc8032Keys;
import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.roster.RosterEntry;

/**
 * Regenerates the published governance golden vectors (docs/specs/gua-governance-v1-vectors.json), which are
 * the byte-for-byte contract an iOS or Android port checks itself against before it is trusted.
 *
 * <p>Run it with {@code ./gradlew governanceVectors}. It is a generator, not a test: the test that matters is
 * {@code CanonicalGovernanceTest}, which reproduces every value in the committed file. Regenerating it is
 * therefore a deliberate act, and a diff in that file is a change to a published wire contract.
 *
 * <p>The keys are the RFC 8032 section 7.1 test constants. They are published, so the signatures below are
 * reproducible by anyone, and nothing real may ever be signed with them.
 */
public final class GovernanceVectorsGenerator {

    private static final ObjectMapper JSON = GovernanceFixtures.mapper();
    private static final Path OUT = Path.of("docs/specs/gua-governance-v1-vectors.json");

    private static final Ed25519.KeyPairB64 TEST1 = Rfc8032Keys.test1();
    private static final Ed25519.KeyPairB64 TEST2 = Rfc8032Keys.test2();

    private GovernanceVectorsGenerator() {}

    public static void main(String[] args) throws Exception {
        ObjectNode root = JSON.createObjectNode();
        root.put("encoding", CanonicalEncoder.ENCODING);
        root.put("decision", "docs/decisions/ADM-007-canonical-encoding-and-member-entries.md, "
                + "section 'Phase 2 objects'");
        ArrayNode notes = root.putArray("notes");
        notes.add("Keys are the RFC 8032 section 7.1 TEST 1 and TEST 2 Ed25519 keys: published test "
                + "constants that must never sign anything real.");
        notes.add("Ed25519 is deterministic, so every signature below is reproducible from the key and the "
                + "canonical bytes.");
        notes.add("A governance threshold counts distinct operatorIds, never key ids (ADM-001 L8). The "
                + "two-keys-one-operator genesis below exists to pin that: it carries two valid signatures "
                + "and still counts as one operator.");
        notes.add("Timestamps are transported as ISO-8601 UTC at millisecond precision; the canonical bytes "
                + "carry their epoch milliseconds.");
        notes.add("A conforming implementation reproduces every canonicalHex, sha256Hex and signature.");

        ObjectNode keys = root.putObject("keys");
        key(keys, "rfc8032-test1", Rfc8032Keys.TEST1_SEED_HEX, Rfc8032Keys.TEST1_PUBLIC_HEX, TEST1);
        key(keys, "rfc8032-test2", Rfc8032Keys.TEST2_SEED_HEX, Rfc8032Keys.TEST2_PUBLIC_HEX, TEST2);

        root.set("genesis", genesisVectors());
        root.set("transitions", transitionVectors());
        root.set("registryContents", contentVectors());
        root.set("registryEpochs", epochVectors());

        Files.createDirectories(OUT.getParent());
        Files.writeString(OUT, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(root) + "\n");
        System.out.println("wrote " + OUT);
    }

    private static ArrayNode genesisVectors() {
        ArrayNode vectors = JSON.createArrayNode();

        FederationGenesis single = new FederationGenesis(FederationGenesis.SCHEMA, "gua-vectors",
                Instant.parse("2026-09-01T00:00:00Z"), FederationGenesis.HASH_SUITE, 1,
                List.of(new GovernanceKey("gov-1", GovernanceKey.ALG, TEST1.publicKeyB64(), "operator-a")),
                Registry.allWireNames(), List.of());
        vectors.add(genesisVector("one operator, one key, threshold 1: what a deployment ships", single,
                Map.of("gov-1", TEST1)));

        // Two keys, ONE operator: two valid signatures, and the threshold still counts one.
        FederationGenesis shared = new FederationGenesis(FederationGenesis.SCHEMA, "gua-vectors-shared",
                Instant.parse("2026-09-01T00:00:00Z"), FederationGenesis.HASH_SUITE, 1,
                List.of(new GovernanceKey("gov-1", GovernanceKey.ALG, TEST1.publicKeyB64(), "operator-a"),
                        new GovernanceKey("gov-2", GovernanceKey.ALG, TEST2.publicKeyB64(), "operator-a")),
                Registry.allWireNames(), List.of());
        ObjectNode sharedVector = genesisVector(
                "two keys held by one operator: two valid signatures count as one operator (ADM-001 L8)",
                shared, Map.of("gov-1", TEST1, "gov-2", TEST2));
        sharedVector.put("distinctOperators", 1);
        vectors.add(sharedVector);

        // Keys given out of order: the canonical bytes sort them, so the hash is order-independent.
        FederationGenesis unordered = new FederationGenesis(FederationGenesis.SCHEMA, "gua-vectors-shared",
                Instant.parse("2026-09-01T00:00:00Z"), FederationGenesis.HASH_SUITE, 1,
                List.of(new GovernanceKey("gov-2", GovernanceKey.ALG, TEST2.publicKeyB64(), "operator-a"),
                        new GovernanceKey("gov-1", GovernanceKey.ALG, TEST1.publicKeyB64(), "operator-a")),
                Registry.allWireNames(), List.of());
        ObjectNode unorderedVector = genesisVector(
                "the same key set listed in reverse: sorting by keyId makes the bytes identical",
                unordered, Map.of("gov-1", TEST1));
        unorderedVector.put("sameBytesAs", "gua-vectors-shared");
        vectors.add(unorderedVector);

        return vectors;
    }

    private static ObjectNode genesisVector(String name, FederationGenesis genesis,
                                            Map<String, Ed25519.KeyPairB64> signers) {
        byte[] canonical = CanonicalGenesis.bytes(genesis);
        String id = CanonicalEncoder.sha256Hex(canonical);
        ObjectNode vector = JSON.createObjectNode();
        vector.put("name", name);
        vector.set("object", JSON.valueToTree(genesis));
        vector.put("canonicalHex", CanonicalEncoder.hex(canonical));
        vector.put("sha256Hex", id);
        vector.put("genesisId", id);
        vector.put("fingerprint", CanonicalGenesis.fingerprint(id));
        signatures(vector, canonical, signers);
        return vector;
    }

    private static ArrayNode transitionVectors() {
        ArrayNode vectors = JSON.createArrayNode();
        String genesisId = CanonicalEncoder.sha256Hex(CanonicalGenesis.bytes(new FederationGenesis(
                FederationGenesis.SCHEMA, "gua-vectors", Instant.parse("2026-09-01T00:00:00Z"),
                FederationGenesis.HASH_SUITE, 1,
                List.of(new GovernanceKey("gov-1", GovernanceKey.ALG, TEST1.publicKeyB64(), "operator-a")),
                Registry.allWireNames(), List.of())));

        GovernanceTransition transition = new GovernanceTransition(GovernanceTransition.SCHEMA, genesisId, 1,
                genesisId, Instant.parse("2026-10-01T00:00:00Z"), 1,
                List.of(new GovernanceKey("gov-2", GovernanceKey.ALG, TEST2.publicKeyB64(), "operator-a")),
                List.of());
        byte[] canonical = CanonicalGovernanceTransition.bytes(transition);
        ObjectNode vector = JSON.createObjectNode();
        vector.put("name", "index 1 rotating the single key; previousHash is the genesis id");
        vector.set("object", JSON.valueToTree(transition));
        vector.put("canonicalHex", CanonicalEncoder.hex(canonical));
        vector.put("sha256Hex", CanonicalEncoder.sha256Hex(canonical));
        // Both the outgoing key and the incoming key sign: the old set authorises, the new set proves it is held.
        signatures(vector, canonical, Map.of("gov-1", TEST1, "gov-2", TEST2));
        vectors.add(vector);
        return vectors;
    }

    private static ArrayNode contentVectors() {
        ArrayNode vectors = JSON.createArrayNode();

        vectors.add(contentVector("empty membership: a registry with no members is still a signed statement",
                HomeserverRegistryContent.of(List.of())));

        vectors.add(contentVector("one attested ACTIVE member with no claims",
                HomeserverRegistryContent.of(List.of(new RegistryMember("hs1",
                        RosterEntry.Status.ACTIVE,
                        "3b1f1a1cf1f0b9f0a8e5f0d7c6b5a49382716059483726150493827160594837",
                        1, true, List.of())))));

        // Members listed out of order, an unattested member (absent hash, which is not an empty one), a
        // suspended member, and a claim exercising optionals, a prefix set and sorted attribute pairs.
        vectors.add(contentVector(
                "members out of order, an unattested member, and a claim with every field shape",
                HomeserverRegistryContent.of(List.of(
                        new RegistryMember("hs2", RosterEntry.Status.SUSPENDED, null, 0, false, List.of()),
                        new RegistryMember("hs1", RosterEntry.Status.ACTIVE,
                                "3b1f1a1cf1f0b9f0a8e5f0d7c6b5a49382716059483726150493827160594837",
                                5, true, List.of(
                                new ClaimPredicate("BR", "72411", "Vivo",
                                        List.of("+5519", "+5511"), "usp.br",
                                        Map.of("department", "eng", "affiliation_kind", "staff"),
                                        null, 100),
                                new ClaimPredicate(null, null, null, List.of(), "", Map.of(),
                                        "https://example.test/claim", -1)))))));
        return vectors;
    }

    private static ObjectNode contentVector(String name, HomeserverRegistryContent content) {
        byte[] canonical = CanonicalHomeserverRegistryContent.bytes(content);
        ObjectNode vector = JSON.createObjectNode();
        vector.put("name", name);
        vector.set("object", JSON.valueToTree(content));
        vector.put("canonicalHex", CanonicalEncoder.hex(canonical));
        vector.put("sha256Hex", CanonicalEncoder.sha256Hex(canonical));
        return vector;
    }

    private static ArrayNode epochVectors() {
        ArrayNode vectors = JSON.createArrayNode();
        String genesisId = "9f2c8a1b0d4e6f5a3c7b9e1d2f4a6c8b0d3e5f7a9c1b3d5e7f9a1c3e5b7d9f10";
        String contentHash = CanonicalHomeserverRegistryContent.hash(HomeserverRegistryContent.of(List.of()));

        RegistryEpoch first = new RegistryEpoch(RegistryEpoch.SCHEMA, Registry.HOMESERVERS, genesisId, 1, "",
                Instant.parse("2026-09-02T00:00:00Z"), contentHash, List.of());
        vectors.add(epochVector("epoch 1: previousEpochHash is the empty string, which is not absent",
                first));

        RegistryEpoch second = new RegistryEpoch(RegistryEpoch.SCHEMA, Registry.HOMESERVERS, genesisId, 2,
                CanonicalRegistryEpoch.hash(first), Instant.parse("2026-09-03T00:00:00Z"), contentHash,
                List.of());
        vectors.add(epochVector("epoch 2: previousEpochHash chains to epoch 1's hash", second));
        return vectors;
    }

    private static ObjectNode epochVector(String name, RegistryEpoch epoch) {
        byte[] canonical = CanonicalRegistryEpoch.bytes(epoch);
        ObjectNode vector = JSON.createObjectNode();
        vector.put("name", name);
        vector.set("object", JSON.valueToTree(epoch));
        vector.put("canonicalHex", CanonicalEncoder.hex(canonical));
        vector.put("sha256Hex", CanonicalEncoder.sha256Hex(canonical));
        signatures(vector, canonical, Map.of("gov-1", TEST1));
        return vector;
    }

    private static void signatures(ObjectNode vector, byte[] canonical,
                                   Map<String, Ed25519.KeyPairB64> signers) {
        ArrayNode array = vector.putArray("signatures");
        signers.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            ObjectNode signature = array.addObject();
            signature.put("keyId", entry.getKey());
            signature.put("keyRef", entry.getValue() == TEST1 ? "rfc8032-test1" : "rfc8032-test2");
            signature.put("signatureB64",
                    Ed25519.sign(Ed25519.privateKey(entry.getValue().privateKeyB64()), canonical));
        });
    }

    private static void key(ObjectNode keys, String ref, String seedHex, String publicHex,
                            Ed25519.KeyPairB64 pair) {
        ObjectNode node = keys.putObject(ref);
        node.put("seedHex", seedHex);
        node.put("publicKeyHex", publicHex);
        node.put("publicKeySpkiB64", pair.publicKeyB64());
        node.put("privateKeyPkcs8B64", pair.privateKeyB64());
    }
}
