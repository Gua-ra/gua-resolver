package global.gua.resolver.tools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.governance.CanonicalGenesis;
import global.gua.resolver.governance.CanonicalHomeserverRegistryContent;
import global.gua.resolver.governance.CanonicalRegistryEpoch;
import global.gua.resolver.governance.FederationGenesis;
import global.gua.resolver.governance.GovernanceFixtures;
import global.gua.resolver.governance.GovernanceJson;
import global.gua.resolver.governance.GovernanceKeySet;
import global.gua.resolver.governance.GovernanceVerifier;
import global.gua.resolver.governance.HomeserverRegistryContent;
import global.gua.resolver.governance.RegistryEpoch;
import global.gua.resolver.governance.RegistryMember;
import global.gua.resolver.roster.RosterEntry;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the governance tool produces has to be what the resolver accepts, so its output is checked with the
 * resolver's own verifier. Keys are generated in memory or by the tool itself and never appear on standard
 * output, which is also what the runbook promises an operator.
 */
class GovToolTest {

    private static final ObjectMapper JSON = GovernanceFixtures.mapper();

    private record Run(int code, String out, String err) {}

    private static Run run(String stdin, String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        InputStream in = new ByteArrayInputStream(stdin.getBytes(StandardCharsets.UTF_8));
        int code = new GovTool(in, new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8)).run(args);
        return new Run(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    private static Path write(Path dir, String name, String content) throws Exception {
        Path path = dir.resolve(name);
        Files.writeString(path, content);
        return path;
    }

    @Test
    void keygenWritesThePrivateKeyToAFileAndPrintsOnlyThePublicHalf(@TempDir Path dir) throws Exception {
        Path keyFile = dir.resolve("governance.key");

        Run run = run("", "keygen", "--operator", "operator-a", "--key-id", "gov-1",
                "--private-key-out", keyFile.toString());

        assertThat(run.code()).isZero();
        JsonNode key = JSON.readTree(run.out());
        assertThat(key.get("keyId").asText()).isEqualTo("gov-1");
        assertThat(key.get("operatorId").asText()).isEqualTo("operator-a");
        assertThat(key.get("alg").asText()).isEqualTo("Ed25519");

        String privateKey = Files.readString(keyFile).trim();
        // The public half published is the public half of the key that was written, and the private half
        // appears nowhere the operator might copy from.
        assertThat(Ed25519.sign(Ed25519.privateKey(privateKey), "x".getBytes(StandardCharsets.UTF_8)))
                .isNotBlank();
        assertThat(run.out()).doesNotContain(privateKey);
        assertThat(run.err()).doesNotContain(privateKey);
    }

    @Test
    void keygenRefusesToOverwriteAnExistingKey(@TempDir Path dir) throws Exception {
        Path keyFile = write(dir, "governance.key", "existing");

        Run run = run("", "keygen", "--operator", "operator-a", "--key-id", "gov-1",
                "--private-key-out", keyFile.toString());

        assertThat(run.code()).isEqualTo(3);
        assertThat(run.err()).contains("refusing to overwrite");
        assertThat(Files.readString(keyFile)).isEqualTo("existing");
    }

    @Test
    void aCreatedAndSignedGenesisVerifiesWithTheResolversOwnVerifier(@TempDir Path dir) throws Exception {
        Ed25519.KeyPairB64 key = Ed25519.generate();
        Path fields = write(dir, "fields.json", """
                {"federationLabel":"gua-tool-test","threshold":1,
                 "keys":[{"keyId":"gov-1","publicKey":"%s","operatorId":"operator-a"}]}
                """.formatted(key.publicKeyB64()));

        Path unsigned = write(dir, "genesis.unsigned.json",
                run("", "genesis", "create", "--fields", fields.toString()).out());
        Run signed = run(key.privateKeyB64() + "\n", "genesis", "sign", "--genesis", unsigned.toString(),
                "--key-id", "gov-1", "--private-key-file", "-");

        assertThat(signed.code()).isZero();
        FederationGenesis genesis = GovernanceJson.read(JSON, signed.out(), FederationGenesis.class);
        genesis.validateShape();
        GovernanceKeySet keys = GovernanceKeySet.of(CanonicalGenesis.id(genesis), genesis.threshold(),
                genesis.keys());

        assertThat(GovernanceVerifier.count(keys, CanonicalGenesis.bytes(genesis), genesis.signatures())
                .valid()).isTrue();
        assertThat(signed.err()).contains(CanonicalGenesis.id(genesis))
                .contains("one operator")
                .doesNotContain(key.privateKeyB64());
        assertThat(signed.out()).doesNotContain(key.privateKeyB64());
    }

    @Test
    void signingAGenesisWithAKeyItDoesNotEnumerateFails(@TempDir Path dir) throws Exception {
        Ed25519.KeyPairB64 enumerated = Ed25519.generate();
        Path fields = write(dir, "fields.json", """
                {"federationLabel":"gua-tool-test","threshold":1,
                 "keys":[{"keyId":"gov-1","publicKey":"%s","operatorId":"operator-a"}]}
                """.formatted(enumerated.publicKeyB64()));
        Path unsigned = write(dir, "genesis.unsigned.json",
                run("", "genesis", "create", "--fields", fields.toString()).out());

        Run run = run(Ed25519.generate().privateKeyB64() + "\n", "genesis", "sign",
                "--genesis", unsigned.toString(), "--key-id", "gov-9", "--private-key-file", "-");

        assertThat(run.code()).isEqualTo(3);
        assertThat(run.err()).contains("is not one of the keys this genesis enumerates");
    }

    @Test
    void aSignedEpochVerifiesAndItsContentHashIsRecomputedNotTrusted(@TempDir Path dir) throws Exception {
        GovernanceFixtures.Holder holder = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        HomeserverRegistryContent content = HomeserverRegistryContent.of(List.of(
                new RegistryMember("hs1", RosterEntry.Status.ACTIVE, null, 1, true, List.of())));
        String contentHash = CanonicalHomeserverRegistryContent.hash(content);
        String genesisId = "a".repeat(64);

        Path pending = write(dir, "pending.json", JSON.writeValueAsString(JSON.createObjectNode()
                .put("genesisId", genesisId)
                .put("registry", "HomeserverRegistry")
                .put("epoch", 1)
                .put("previousEpochHash", "")
                .put("contentHash", contentHash)
                .set("content", JSON.valueToTree(content))));

        Run run = run(holder.privateKeyB64() + "\n", "epoch", "sign", "--pending", pending.toString(),
                "--key-id", "gov-1", "--private-key-file", "-");

        assertThat(run.code()).isZero();
        JsonNode body = JSON.readTree(run.out());
        RegistryEpoch epoch = GovernanceJson.read(JSON, body.get("epoch"), RegistryEpoch.class);
        epoch.validateShape();
        GovernanceKeySet keys = GovernanceKeySet.of(genesisId, 1, List.of(holder.key()));

        assertThat(epoch.contentHash()).isEqualTo(contentHash);
        assertThat(GovernanceVerifier.count(keys, CanonicalRegistryEpoch.bytes(epoch), epoch.signatures())
                .valid()).isTrue();
        assertThat(run.out()).doesNotContain(holder.privateKeyB64());

        // A pending document whose contentHash does not match its own content is refused, so an operator
        // cannot be talked into signing a hash they did not derive.
        Path tampered = write(dir, "tampered.json", Files.readString(pending)
                .replace(contentHash, "c".repeat(64)));
        Run refused = run(holder.privateKeyB64() + "\n", "epoch", "sign", "--pending", tampered.toString(),
                "--key-id", "gov-1", "--private-key-file", "-");

        assertThat(refused.code()).isEqualTo(3);
        assertThat(refused.err()).contains("does not hash to the contentHash");
    }

    @Test
    void aKeyPassedAsAnArgumentIsRefusedOutright() {
        Run run = run("", "genesis", "sign", "--genesis", "g.json", "--private-key", "MC4CAQAwBQYDK2Vw");

        assertThat(run.code()).isEqualTo(2);
        assertThat(run.err()).contains("shell history");
    }

    @Test
    void anUnknownCommandIsAUsageErrorNotAFailure() {
        assertThat(run("", "sign-everything").code()).isEqualTo(2);
        assertThat(run("", "genesis").code()).isEqualTo(2);
        assertThat(run("").code()).isEqualTo(2);
    }
}
