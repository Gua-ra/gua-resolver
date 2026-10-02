package global.gua.resolver.tools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.MemberAttestation;
import global.gua.resolver.roster.MemberEntryJson;
import global.gua.resolver.roster.MemberEntryVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the tool produces has to be what the resolver accepts, so its output is checked with the same
 * verifier the resolver runs. Keys are generated in memory and piped through standard input, which is also
 * the way the runbook tells an operator to handle them.
 */
class MemberEntryToolTest {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final MemberEntryVerifier VERIFIER =
            new MemberEntryVerifier(MemberEntryVerifier.DEFAULT_MAX_LIFETIME);

    private record Run(int code, String out, String err) {}

    private static Run run(String stdin, String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        InputStream in = new ByteArrayInputStream(stdin.getBytes(StandardCharsets.UTF_8));
        int code = new MemberEntryTool(in, new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8)).run(args);
        return new Run(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    private static String fields(String signingKey, String keyId, long sequence, String extra) {
        return """
                {"id":"hs1","serverName":"hs1.gua.test","baseUrl":"https://matrix.hs1.gua.test",
                 "masIssuer":"https://account.hs1.gua.test/","region":"BR","searchVisibility":"GLOBAL",
                 "searchGroups":[],"signingKey":"%s","keyId":"%s","sequence":%d,
                 "notBefore":"2026-09-11T00:00:00Z","lifetimeDays":400%s}
                """.formatted(signingKey, keyId, sequence, extra);
    }

    private static java.nio.file.Path write(java.nio.file.Path dir, String name, String content)
            throws Exception {
        java.nio.file.Path path = dir.resolve(name);
        java.nio.file.Files.writeString(path, content);
        return path;
    }

    private static Homeserver homeserver(JsonNode body) {
        JsonNode h = body.get("homeserver");
        return new Homeserver(h.get("id").asText(), h.get("serverName").asText(),
                h.get("baseUrl").asText(), h.get("masIssuer").asText(),
                h.get("region").isNull() ? null : h.get("region").asText(), 1, true,
                h.get("signingKey").asText(),
                Homeserver.SearchVisibility.valueOf(h.get("searchVisibility").asText()), List.of());
    }

    @Test
    void aSignedEntryVerifiesWithTheResolversOwnVerifierAndLeaksNoKeyMaterial(
            @org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        Ed25519.KeyPairB64 key = Ed25519.generate();
        java.nio.file.Path fields = write(dir, "fields.json",
                fields(key.publicKeyB64(), "hs1-1", 1, ""));

        Run run = run(key.privateKeyB64() + "\n", "sign", "--fields", fields.toString(),
                "--private-key-file", "-");

        assertThat(run.code()).isZero();
        JsonNode body = JSON.readTree(run.out());
        MemberAttestation member = MemberEntryJson.readMember(JSON, body.get("member"));
        MemberEntryVerifier.Result result =
                VERIFIER.verify(homeserver(body), member, Instant.parse("2026-10-01T00:00:00Z"));
        assertThat(result.valid()).as(result.reason()).isTrue();
        assertThat(run.out()).doesNotContain(key.privateKeyB64());
        assertThat(run.err()).doesNotContain(key.privateKeyB64())
                .contains(result.entryHash());
    }

    @Test
    void signingWithAKeyThatDoesNotMatchTheDeclaredPublicKeyFails(
            @org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        java.nio.file.Path fields = write(dir, "fields.json",
                fields(Ed25519.generate().publicKeyB64(), "hs1-1", 1, ""));

        Run run = run(Ed25519.generate().privateKeyB64() + "\n", "sign", "--fields", fields.toString(),
                "--private-key-file", "-");

        assertThat(run.code()).isEqualTo(3);
        assertThat(run.err()).contains("does not verify");
    }

    @Test
    void aRotationCarriesBothSignaturesAndChainsToThePreviousKey(
            @org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        Ed25519.KeyPairB64 previous = Ed25519.generate();
        Ed25519.KeyPairB64 next = Ed25519.generate();
        java.nio.file.Path fields = write(dir, "rotate.json", fields(next.publicKeyB64(), "hs1-2", 2,
                ",\"previousKeyId\":\"hs1-1\",\"previousSigningKey\":\"" + previous.publicKeyB64() + "\""));

        // Both keys on standard input: the new key first, as the runbook says.
        Run run = run(next.privateKeyB64() + "\n" + previous.privateKeyB64() + "\n", "rotate",
                "--fields", fields.toString(), "--private-key-file", "-",
                "--previous-private-key-file", "-");

        assertThat(run.code()).isZero();
        JsonNode body = JSON.readTree(run.out());
        MemberAttestation member = MemberEntryJson.readMember(JSON, body.get("member"));
        assertThat(member.signatures()).hasSize(2);
        MemberEntryVerifier.Prior prior = new MemberEntryVerifier.Prior("hs1-1",
                previous.publicKeyB64(), 1, null);
        assertThat(VERIFIER.verify(homeserver(body), member, Instant.parse("2026-10-01T00:00:00Z"), prior)
                .valid()).isTrue();
    }

    @Test
    void verifyReportsATamperedRosterAndExitsNonZero(
            @org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        Ed25519.KeyPairB64 key = Ed25519.generate();
        java.nio.file.Path fields = write(dir, "fields.json",
                fields(key.publicKeyB64(), "hs1-1", 1, ""));
        JsonNode entry = JSON.readTree(run(key.privateKeyB64() + "\n", "sign",
                "--fields", fields.toString(), "--private-key-file", "-").out());
        String roster = """
                {"version":1,"issuedAt":"2026-10-01T00:00:00Z","logCheckpoint":{"merkleRoot":"r","size":1},
                 "authoritySignatures":[],"entries":[{"homeserver":%s,"claims":[],
                 "admittedAt":"2026-09-11T00:00:00Z","status":"ACTIVE","member":%s}]}
                """.formatted(entry.get("homeserver"), entry.get("member"));

        Run good = run("", "verify", "--roster",
                write(dir, "roster.json", roster).toString(), "--at", "2026-10-01T00:00:00Z");
        assertThat(good.code()).isZero();
        assertThat(good.out()).contains("ok         hs1");

        String tampered = roster.replace("https://matrix.hs1.gua.test", "https://attacker.gua.test");
        Run bad = run("", "verify", "--roster",
                write(dir, "tampered.json", tampered).toString(), "--at", "2026-10-01T00:00:00Z");
        assertThat(bad.code()).isEqualTo(3);
        assertThat(bad.out()).contains("invalid    hs1").contains("1 ACTIVE invalid");
    }

    @Test
    void aKeyPassedAsAnArgumentIsRefusedOutright() {
        Run run = run("", "sign", "--fields", "fields.json", "--private-key", "MC4CAQAwBQYDK2Vw");

        assertThat(run.code()).isEqualTo(2);
        assertThat(run.err()).contains("shell history");
    }
}
