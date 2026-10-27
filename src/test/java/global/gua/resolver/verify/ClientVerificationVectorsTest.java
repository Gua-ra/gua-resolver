package global.gua.resolver.verify;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.crypto.Rfc8032Keys;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.placement.rules.WeightedFallbackRule;
import global.gua.resolver.policy.CanonicalDelegatedRules;
import global.gua.resolver.policy.CanonicalRoutingPolicy;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicyVerifier;
import global.gua.resolver.roster.CanonicalRoster;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterVerifier;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The committed client-verification vectors are the contract the web, iOS and Android verifiers test against.
 * Every value in the file is reproduced here with the production code, so the file cannot drift from it.
 */
class ClientVerificationVectorsTest {

    private static final Path VECTORS = Path.of("docs/specs/gua-client-verification-v1-vectors.json");
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final HexFormat HEX = HexFormat.of();

    private static JsonNode vectors() throws Exception {
        return JSON.readTree(Files.readString(VECTORS));
    }

    private static List<ResolverProperties.TrustedKey> trustedKeys(JsonNode list) {
        List<ResolverProperties.TrustedKey> keys = new ArrayList<>();
        for (JsonNode k : list) {
            ResolverProperties.TrustedKey t = new ResolverProperties.TrustedKey();
            t.setId(k.get("id").asText());
            t.setPublicKey(k.get("publicKeySpkiB64").asText());
            keys.add(t);
        }
        return keys;
    }

    private static RosterVerifier rosterVerifier(JsonNode v) {
        ResolverProperties props = new ResolverProperties();
        props.getAuthority().setThreshold(v.get("threshold").asInt());
        props.getAuthority().setTrustedKeys(trustedKeys(v.get("trustedKeys")));
        return new RosterVerifier(props);
    }

    private static RoutingPolicyVerifier policyVerifier(JsonNode v) {
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setRequireSignatures(true);
        props.getPolicy().setSignatureThreshold(v.get("threshold").asInt());
        props.getPolicy().setTrustedKeys(trustedKeys(v.get("trustedKeys")));
        return new RoutingPolicyVerifier(props);
    }

    private static Ed25519.KeyPairB64 key(JsonNode root, String ref) {
        JsonNode k = root.get("keys").get(ref);
        return Rfc8032Keys.pair(k.get("seedHex").asText(), k.get("publicKeyHex").asText());
    }

    private static byte[] canonical(JsonNode v, SignedRoster roster) {
        return "legacy".equals(v.get("form").asText()) ? CanonicalRoster.legacyBytes(roster) : CanonicalRoster.bytes(roster);
    }

    @Test
    void everyKeyMatchesItsSeedAndSpkiEncoding() throws Exception {
        JsonNode root = vectors();
        root.get("keys").fields().forEachRemaining(entry -> {
            JsonNode k = entry.getValue();
            byte[] spki = java.util.Base64.getDecoder().decode(k.get("publicKeySpkiB64").asText());
            assertThat(HEX.formatHex(spki, 12, 44)).as(entry.getKey()).isEqualTo(k.get("publicKeyHex").asText());
            if (k.has("seedHex")) {
                Ed25519.KeyPairB64 pair = key(root, entry.getKey());
                assertThat(pair.publicKeyB64()).isEqualTo(k.get("publicKeySpkiB64").asText());
                assertThat(pair.privateKeyB64()).isEqualTo(k.get("privateKeyPkcs8B64").asText());
                String sig = Ed25519.sign(Ed25519.privateKey(pair.privateKeyB64()), new byte[] {1});
                assertThat(Ed25519.verify(Ed25519.publicKey(pair.publicKeyB64()), new byte[] {1}, sig)).isTrue();
            }
        });
    }

    @Test
    void everyInstantTruncatesToTheListedEpochMilliseconds() throws Exception {
        for (JsonNode v : vectors().get("instants")) {
            assertThat(Instant.parse(v.get("iso").asText()).toEpochMilli()).as(v.get("iso").asText())
                    .isEqualTo(Long.parseLong(v.get("epochMs").asText()));
        }
    }

    @Test
    void everyRosterVectorReproducesItsBytesAndVerdict() throws Exception {
        JsonNode root = vectors();
        for (JsonNode v : root.get("rosters")) {
            String name = v.get("name").asText();
            SignedRoster roster = JSON.treeToValue(v.get("roster"), SignedRoster.class);
            byte[] canonical = canonical(v, roster);
            assertThat(new String(canonical, StandardCharsets.UTF_8)).as(name).isEqualTo(v.get("canonicalUtf8").asText());
            assertThat(HEX.formatHex(canonical)).as(name).isEqualTo(v.get("canonicalHex").asText());
            assertThat(MerkleTree.sha256Hex(canonical)).as(name).isEqualTo(v.get("sha256Hex").asText());

            int valid = 0;
            TreeSet<String> counted = new TreeSet<>();
            for (SignedRoster.AuthoritySignature s : roster.authoritySignatures()) {
                for (ResolverProperties.TrustedKey k : trustedKeys(v.get("trustedKeys"))) {
                    if (k.getId().equals(s.authorityKeyId()) && counted.add(k.getId())
                            && Ed25519.verify(Ed25519.publicKey(k.getPublicKey()), canonical, s.signatureB64())) {
                        valid++;
                    }
                }
            }
            assertThat(valid).as(name).isEqualTo(v.get("validSignatures").asInt());
            assertThat(valid >= v.get("threshold").asInt()).as(name).isEqualTo(v.get("verified").asBoolean());
            if ("v1".equals(v.get("form").asText())) {
                assertThat(rosterVerifier(v).isVerified(roster)).as(name).isEqualTo(v.get("verified").asBoolean());
            }
            v.get("signatureKeyRefs").fields().forEachRemaining(ref -> {
                Ed25519.KeyPairB64 pair = key(root, ref.getValue().asText());
                String expected = roster.authoritySignatures().stream()
                        .filter(s -> s.authorityKeyId().equals(ref.getKey())).findFirst().orElseThrow().signatureB64();
                assertThat(Ed25519.sign(Ed25519.privateKey(pair.privateKeyB64()), canonical)).as(name).isEqualTo(expected);
            });
        }
    }

    @Test
    void everyRosterRejectionIsRefused() throws Exception {
        for (JsonNode v : vectors().get("rosterRejections")) {
            String name = v.get("name").asText();
            if (v.path("clientOnly").asBoolean(false)) {
                assertThat(v.get("form").asText()).as(name).isEqualTo("mixed");
                continue;
            }
            SignedRoster roster = JSON.treeToValue(v.get("roster"), SignedRoster.class);
            byte[] canonical = canonical(v, roster);
            int valid = 0;
            TreeSet<String> counted = new TreeSet<>();
            for (SignedRoster.AuthoritySignature s : roster.authoritySignatures()) {
                for (ResolverProperties.TrustedKey k : trustedKeys(v.get("trustedKeys"))) {
                    if (k.getId().equals(s.authorityKeyId()) && counted.add(k.getId())
                            && Ed25519.verify(Ed25519.publicKey(k.getPublicKey()), canonical, s.signatureB64())) {
                        valid++;
                    }
                }
            }
            assertThat(valid).as(name).isLessThan(v.get("threshold").asInt());
            assertThat(v.get("verified").asBoolean()).as(name).isFalse();
            if ("v1".equals(v.get("form").asText())) {
                assertThat(rosterVerifier(v).isVerified(roster)).as(name).isFalse();
            }
        }
    }

    @Test
    void theLogVectorsReproduceLeavesRootsAndProofs() throws Exception {
        JsonNode log = vectors().get("log");
        List<String> leafHashes = new ArrayList<>();
        for (JsonNode e : log.get("events")) {
            String homeserverId = e.get("homeserverId").isNull() ? "" : e.get("homeserverId").asText();
            String leafData = e.get("index").asLong() + "|" + e.get("type").asText() + "|" + homeserverId + "|"
                    + e.get("payloadHash").asText() + "|" + Instant.parse(e.get("recordedAt").asText()).toEpochMilli();
            assertThat(leafData).isEqualTo(e.get("leafDataUtf8").asText());
            String leafHash = MerkleTree.leafHash(leafData.getBytes(StandardCharsets.UTF_8));
            assertThat(leafHash).isEqualTo(e.get("leafHashHex").asText());
            leafHashes.add(leafHash);
        }
        for (JsonNode r : log.get("roots")) {
            assertThat(MerkleTree.root(leafHashes.subList(0, r.get("size").asInt())))
                    .as("root at size " + r.get("size")).isEqualTo(r.get("rootHex").asText());
        }
        for (JsonNode p : log.get("consistencyProofs")) {
            int first = p.get("first").asInt();
            int second = p.get("second").asInt();
            List<String> proof = new ArrayList<>();
            p.get("proof").forEach(n -> proof.add(n.asText()));
            assertThat(MerkleTree.consistencyProof(leafHashes, first, second)).as(first + "," + second).isEqualTo(proof);
            assertThat(MerkleTree.verifyConsistency(first, second, p.get("oldRootHex").asText(),
                    p.get("newRootHex").asText(), proof)).as(first + "," + second).isTrue();
        }
        for (JsonNode p : log.get("invalidConsistencyProofs")) {
            List<String> proof = new ArrayList<>();
            p.get("proof").forEach(n -> proof.add(n.asText()));
            assertThat(MerkleTree.verifyConsistency(p.get("first").asInt(), p.get("second").asInt(),
                    p.get("oldRootHex").asText(), p.get("newRootHex").asText(), proof))
                    .as(p.get("name").asText()).isFalse();
        }
    }

    @Test
    void everyPolicyVectorReproducesItsBytesAndVerdict() throws Exception {
        JsonNode root = vectors();
        List<JsonNode> all = new ArrayList<>();
        root.get("policies").forEach(all::add);
        root.get("policyRejections").forEach(all::add);
        for (JsonNode v : all) {
            String name = v.get("name").asText();
            RoutingPolicyBundle bundle = JSON.treeToValue(v.get("bundle"), RoutingPolicyBundle.class);
            byte[] canonical = CanonicalRoutingPolicy.bytes(bundle);
            assertThat(new String(canonical, StandardCharsets.UTF_8)).as(name).isEqualTo(v.get("canonicalUtf8").asText());
            assertThat(HEX.formatHex(canonical)).as(name).isEqualTo(v.get("canonicalHex").asText());
            assertThat(MerkleTree.sha256Hex(canonical)).as(name).isEqualTo(v.get("sha256Hex").asText());
            for (JsonNode z : v.get("delegatedRules")) {
                byte[] delegated = CanonicalDelegatedRules.bytes(bundle.policyId(), bundle.version(),
                        z.get("zoneId").asText(), bundle.rules());
                assertThat(HEX.formatHex(delegated)).as(name + " " + z.get("zoneId")).isEqualTo(z.get("canonicalHex").asText());
            }
            RoutingPolicyVerifier verifier = policyVerifier(v);
            assertThat(verifier.isVerified(bundle)).as(name).isEqualTo(v.get("verified").asBoolean());
            List<String> zones = new ArrayList<>();
            v.get("delegateVerifiedZones").forEach(z -> zones.add(z.asText()));
            assertThat(new TreeSet<>(verifier.delegateVerifiedZones(bundle))).as(name).containsExactlyElementsOf(zones);
        }
        for (JsonNode v : root.get("policyRejections")) {
            assertThat(v.get("verified").asBoolean()).as(v.get("name").asText()).isFalse();
        }
    }

    @Test
    void everyPlacementVectorReproducesTheReferenceDecision() throws Exception {
        JsonNode root = vectors();
        Map<String, JsonNode> rosters = Map.of(
                "r1", root.get("rosters").get(0), "r2", root.get("rosters").get(1));
        Map<String, JsonNode> policies = Map.of(
                "br-policy v3", root.get("policies").get(0),
                "br-policy v3 without the sp-zone delegate signature", root.get("policies").get(1));
        for (JsonNode v : root.get("placements")) {
            String name = v.get("name").asText();
            JsonNode rv = rosters.get(v.get("rosterRef").asText());
            SignedRoster roster = JSON.treeToValue(rv.get("roster"), SignedRoster.class);
            RoutingPolicyBundle policy = null;
            List<ResolverProperties.TrustedKey> policyKeys = List.of();
            if (!v.get("policyRef").isNull()) {
                JsonNode pv = policies.get(v.get("policyRef").asText());
                policy = JSON.treeToValue(pv.get("bundle"), RoutingPolicyBundle.class);
                policyKeys = trustedKeys(pv.get("trustedKeys"));
            }
            JsonNode c = v.get("context");
            List<String> affiliations = new ArrayList<>();
            c.path("affiliations").forEach(a -> affiliations.add(a.asText()));
            Map<String, String> attributes = new java.util.TreeMap<>();
            c.path("attributes").fields().forEachRemaining(e -> attributes.put(e.getKey(), e.getValue().asText()));
            PlacementContext ctx = new PlacementContext(c.get("phone").asText(), text(c, "country"), text(c, "mccmnc"),
                    text(c, "carrier"), text(c, "regionHint"), affiliations, attributes, false);

            ResolverVerifier verifier = new ResolverVerifier(trustedKeys(rv.get("trustedKeys")),
                    rv.get("threshold").asInt(), policyKeys, 1);
            PlacementDecision d = verifier.reproduceNewAccountDecision(ctx, roster, policy);
            assertThat(d.homeserver().id()).as(name).isEqualTo(v.get("expectedHomeserverId").asText());
            assertThat(d.rule()).as(name).isEqualTo(v.get("expectedRule").asText());
            assertThat(d.ruleId()).as(name).isEqualTo(v.get("expectedRuleId").asText());
            if (v.has("fallback")) {
                JsonNode f = v.get("fallback");
                assertThat(ctx.canonicalRoutingKey()).as(name).isEqualTo(f.get("routingKeyUtf8").asText());
                List<Homeserver> candidates = roster.activeEntries().stream().map(RosterEntry::homeserver)
                        .filter(Homeserver::acceptsNew).sorted(java.util.Comparator.comparing(Homeserver::id)).toList();
                assertThat(WeightedFallbackRule.stableHash(ctx, roster.version(), candidates)).as(name)
                        .isEqualTo(f.get("stableHash").asInt());
            }
        }
    }

    @Test
    void everyResolveAnswerVectorLocatesAsExpected() throws Exception {
        JsonNode root = vectors();
        Map<String, JsonNode> rosters = Map.of("r2", root.get("rosters").get(1), "prod-2026-10-27", root.get("rosters").get(3));
        for (JsonNode v : root.get("resolveAnswers")) {
            SignedRoster roster = JSON.treeToValue(rosters.get(v.get("rosterRef").asText()).get("roster"), SignedRoster.class);
            JsonNode a = v.get("answer");
            assertThat(ResolverVerifier.locate(a.get("serverName").asText(), a.get("baseUrl").asText(),
                    text(a, "masIssuer"), roster).name()).as(v.get("name").asText()).isEqualTo(v.get("expected").asText());
        }
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }
}
