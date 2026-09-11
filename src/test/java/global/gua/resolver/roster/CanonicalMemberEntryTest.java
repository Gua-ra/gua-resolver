package global.gua.resolver.roster;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.Rfc8032Keys;
import global.gua.resolver.domain.Homeserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The published golden vectors (docs/specs/gua-lp-v1-vectors.json) are the contract the iOS and Android ports
 * verify against, so they are recomputed here byte for byte: primitives, member-entry canonical bytes, object
 * hashes, deterministic Ed25519 signatures, and every case a conforming verifier must refuse.
 */
class CanonicalMemberEntryTest {

    private static final Path VECTORS = Path.of("docs/specs/gua-lp-v1-vectors.json");
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();

    private static JsonNode vectors() throws Exception {
        return JSON.readTree(Files.readString(VECTORS));
    }

    private static Homeserver homeserver(JsonNode n) {
        JsonNode region = n.get("region");
        List<String> groups = new ArrayList<>();
        n.get("searchGroups").forEach(g -> groups.add(g.asText()));
        return new Homeserver(n.get("id").asText(), n.get("serverName").asText(),
                n.get("baseUrl").asText(), n.get("masIssuer").asText(),
                region == null || region.isNull() ? null : region.asText(),
                1, true, n.get("signingKey").asText(),
                Homeserver.SearchVisibility.valueOf(n.get("searchVisibility").asText()), groups);
    }

    private static MemberAttestation member(JsonNode n) {
        return MemberEntryJson.readMember(JSON, n);
    }

    private static Ed25519.KeyPairB64 key(JsonNode root, String ref) {
        JsonNode k = root.get("keys").get(ref);
        return Rfc8032Keys.pair(k.get("seedHex").asText(), k.get("publicKeyHex").asText());
    }

    @Test
    void theRfc8032TestKeysAreTheOnesTheVectorsName() throws Exception {
        JsonNode root = vectors();
        for (String ref : List.of("rfc8032-test1", "rfc8032-test2")) {
            Ed25519.KeyPairB64 kp = key(root, ref);
            assertThat(kp.publicKeyB64()).isEqualTo(root.get("keys").get(ref).get("publicKeySpkiB64").asText());
            assertThat(kp.privateKeyB64())
                    .isEqualTo(root.get("keys").get(ref).get("privateKeyPkcs8B64").asText());
        }
        // RFC 8032 TEST 1: the signature over the empty message, so a wrong constant cannot go unnoticed.
        Ed25519.KeyPairB64 test1 = key(root, "rfc8032-test1");
        String signature = Ed25519.sign(Ed25519.privateKey(test1.privateKeyB64()), new byte[0]);
        assertThat(CanonicalEncoder.hex(java.util.Base64.getDecoder().decode(signature))).isEqualTo(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970"
                        + "1cf9b46bd25bf5f0595bbe24655141438e7a100b");
        assertThat(Ed25519.verify(Ed25519.publicKey(test1.publicKeyB64()), new byte[0], signature)).isTrue();
    }

    @Test
    void everyPrimitiveVectorReproduces() throws Exception {
        JsonNode root = vectors();
        for (JsonNode v : root.get("primitives")) {
            JsonNode value = v.get("value");
            CanonicalEncoder e = CanonicalEncoder.raw();
            switch (v.get("type").asText()) {
                case "string" -> e.string(value.asText());
                case "int64" -> e.int64(Long.parseLong(value.asText()));
                case "bool" -> e.bool(value.asBoolean());
                case "optionalString" -> e.optionalString(value.isNull() ? null : value.asText());
                case "stringSet" -> e.stringSet(list(value));
                case "stringList" -> e.stringList(list(value));
                case "enum" -> e.enumName(Homeserver.SearchVisibility.valueOf(value.asText()));
                default -> throw new IllegalStateException("unknown vector type " + v.get("type"));
            }
            assertThat(CanonicalEncoder.hex(e.toByteArray())).as(v.get("name").asText())
                    .isEqualTo(v.get("hex").asText());
        }
    }

    @Test
    void everyMemberEntryVectorReproducesItsBytesHashAndSignatures() throws Exception {
        JsonNode root = vectors();
        assertThat(root.get("encoding").asText()).isEqualTo(CanonicalEncoder.ENCODING);
        MemberEntryVerifier verifier = new MemberEntryVerifier(MemberEntryVerifier.DEFAULT_MAX_LIFETIME);

        for (JsonNode v : root.get("memberEntries")) {
            String name = v.get("name").asText();
            Homeserver hs = homeserver(v.get("homeserver"));
            MemberAttestation m = member(v.get("member"));
            assertThat(m.schema()).isEqualTo(CanonicalMemberEntry.SCHEMA);

            byte[] canonical = CanonicalMemberEntry.bytes(hs, m);
            assertThat(CanonicalEncoder.hex(canonical)).as(name).isEqualTo(v.get("canonicalHex").asText());
            assertThat(CanonicalEncoder.sha256Hex(canonical)).as(name).isEqualTo(v.get("sha256Hex").asText());
            assertThat(m.notBefore().toEpochMilli()).isEqualTo(v.get("notBeforeEpochMs").asLong());
            assertThat(m.notAfter().toEpochMilli()).isEqualTo(v.get("notAfterEpochMs").asLong());

            // Deterministic: re-signing the same bytes with the same key reproduces the published signature.
            Ed25519.KeyPairB64 kp = key(root, v.get("signingKeyRef").asText());
            MemberAttestation resigned = MemberEntrySigner.sign(hs, m.withSignatures(List.of()),
                    m.keyId(), kp.privateKeyB64());
            assertThat(resigned.signatures().get(0).signatureB64())
                    .as(name).isEqualTo(signatureFor(m, m.keyId()));

            MemberEntryVerifier.Prior prior = prior(root, v.get("previous"));
            MemberEntryVerifier.Result result = verifier.verify(hs, m, m.notBefore(), prior);
            assertThat(result.valid()).as("%s: %s", name, result.reason()).isTrue();
            assertThat(result.entryHash()).isEqualTo(v.get("sha256Hex").asText());
        }
    }

    @Test
    void everyRejectionVectorIsRefused() throws Exception {
        JsonNode root = vectors();
        MemberEntryVerifier verifier = new MemberEntryVerifier(MemberEntryVerifier.DEFAULT_MAX_LIFETIME);

        for (JsonNode v : root.get("rejections")) {
            String name = v.get("name").asText();
            Homeserver hs = homeserver(v.get("homeserver"));
            MemberAttestation m;
            try {
                m = member(v.get("member"));
            } catch (MemberEntryJson.MalformedMemberEntryException strictParseRefused) {
                continue;   // the strict transport parse is the refusal for this vector
            }
            Instant at = m.notBefore() == null ? Instant.now() : m.notBefore();
            MemberEntryVerifier.Result result = verifier.verify(hs, m, at, prior(root, v.get("previous")));
            assertThat(result.valid()).as(name).isFalse();
            assertThat(result.reason()).as(name).isNotBlank();
        }
    }

    @Test
    void theStrictTransportParseRefusesAnUnknownFieldInTheSignedSubObject() throws Exception {
        JsonNode member = vectors().get("memberEntries").get(0).get("member").deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) member).put("weight", 100);

        assertThatThrownBy(() -> MemberEntryJson.readMember(JSON, member))
                .isInstanceOf(MemberEntryJson.MalformedMemberEntryException.class);
    }

    private static MemberEntryVerifier.Prior prior(JsonNode root, JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        return new MemberEntryVerifier.Prior(node.get("keyId").asText(), node.get("signingKey").asText(),
                node.get("sequence").asLong(),
                node.hasNonNull("entryHash") ? node.get("entryHash").asText() : null);
    }

    private static String signatureFor(MemberAttestation m, String keyId) {
        return m.signatures().stream().filter(s -> s.keyId().equals(keyId)).findFirst().orElseThrow()
                .signatureB64();
    }

    private static List<String> list(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(n -> values.add(n.asText()));
        return values;
    }
}
