package global.gua.resolver.verify;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
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
import global.gua.resolver.policy.RoutingPolicyVerifier.RoutingPolicyVerificationException;
import global.gua.resolver.roster.CanonicalRoster;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterForm;
import global.gua.resolver.roster.RosterVerifier;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientVerificationVectorsTest {

    private static final Path VECTORS = Path.of("docs/specs/gua-client-verification-v1-vectors.json");
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final HexFormat HEX = HexFormat.of();

    private static JsonNode vectors() throws Exception {
        return JSON.readTree(Files.readString(VECTORS));
    }

    private static Map<String, JsonNode> byRef(JsonNode vectors) {
        Map<String, JsonNode> out = new HashMap<>();
        vectors.forEach(v -> {
            if (v.has("ref")) {
                out.put(v.get("ref").asText(), v);
            }
        });
        return out;
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

    private static RosterForm form(JsonNode v) {
        return RosterForm.valueOf(v.get("form").asText().toUpperCase(Locale.ROOT));
    }

    private static Ed25519.KeyPairB64 key(JsonNode root, String ref) {
        JsonNode k = root.get("keys").get(ref);
        return Rfc8032Keys.pair(k.get("seedHex").asText(), k.get("publicKeyHex").asText());
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }

    @Test
    void theCommittedFileIsWhatTheGeneratorWrites() throws Exception {
        assertThat(Files.readString(VECTORS)).isEqualTo(ClientVerificationVectorsGenerator.render());
    }

    @Test
    void everyKeyMatchesItsSeedAndSpkiEncoding() throws Exception {
        JsonNode root = vectors();
        root.get("keys").properties().forEach(entry -> {
            JsonNode k = entry.getValue();
            byte[] spki = Base64.getDecoder().decode(k.get("publicKeySpkiB64").asText());
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
    void everyRosterVectorReproducesItsFormBytesAndVerdict() throws Exception {
        JsonNode root = vectors();
        for (JsonNode v : root.get("rosters")) {
            String name = v.get("name").asText();
            SignedRoster roster = JSON.treeToValue(v.get("roster"), SignedRoster.class);
            RosterForm form = form(v);
            assertThat(RosterForm.of(v.get("roster"))).as(name).hasValue(form);

            byte[] canonical = CanonicalRoster.bytes(roster, form);
            assertThat(new String(canonical, StandardCharsets.UTF_8)).as(name)
                    .isEqualTo(v.get("canonicalUtf8").asText());
            assertThat(HEX.formatHex(canonical)).as(name).isEqualTo(v.get("canonicalHex").asText());
            assertThat(MerkleTree.sha256Hex(canonical)).as(name).isEqualTo(v.get("sha256Hex").asText());

            RosterVerifier verifier = rosterVerifier(v);
            assertThat(verifier.countValidSignatures(roster, form)).as(name)
                    .isEqualTo(v.get("validSignatures").asInt());
            assertThat(verifier.isVerified(roster, form)).as(name).isEqualTo(v.get("verified").asBoolean());

            v.path("signatureKeyRefs").properties().forEach(ref -> {
                Ed25519.KeyPairB64 pair = key(root, ref.getValue().asText());
                String expected = roster.authoritySignatures().stream()
                        .filter(s -> s.authorityKeyId().equals(ref.getKey())).findFirst().orElseThrow().signatureB64();
                assertThat(Ed25519.sign(Ed25519.privateKey(pair.privateKeyB64()), canonical)).as(name)
                        .isEqualTo(expected);
            });
        }
    }

    @Test
    void everyRosterRejectionIsRefused() throws Exception {
        for (JsonNode v : vectors().get("rosterRejections")) {
            String name = v.get("name").asText();
            assertThat(v.path("verified").asBoolean(false)).as(name).isFalse();
            if ("mixed".equals(v.get("form").asText())) {
                assertThat(RosterForm.of(v.get("roster"))).as(name).isEmpty();
                continue;
            }
            SignedRoster roster = JSON.treeToValue(v.get("roster"), SignedRoster.class);
            assertThat(rosterVerifier(v).isVerified(roster, form(v))).as(name).isFalse();
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
            assertThat(MerkleTree.consistencyProof(leafHashes, first, second)).as(first + "," + second)
                    .isEqualTo(proof);
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
            assertThat(new String(canonical, StandardCharsets.UTF_8)).as(name)
                    .isEqualTo(v.get("canonicalUtf8").asText());
            assertThat(HEX.formatHex(canonical)).as(name).isEqualTo(v.get("canonicalHex").asText());
            assertThat(MerkleTree.sha256Hex(canonical)).as(name).isEqualTo(v.get("sha256Hex").asText());
            for (JsonNode z : v.get("delegatedRules")) {
                byte[] delegated = CanonicalDelegatedRules.bytes(bundle.policyId(), bundle.version(),
                        z.get("zoneId").asText(), bundle.rules());
                assertThat(HEX.formatHex(delegated)).as(name + " " + z.get("zoneId"))
                        .isEqualTo(z.get("canonicalHex").asText());
            }
            RoutingPolicyVerifier verifier = RoutingPolicyVerifier.forKeys(trustedKeys(v.get("trustedKeys")),
                    v.get("threshold").asInt());
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
    void everyPolicyValidityVectorFollowsTheWindowRule() throws Exception {
        JsonNode root = vectors();
        Map<String, JsonNode> policies = byRef(root.get("policies"));
        for (JsonNode v : root.get("policyValidity")) {
            String name = v.get("name").asText();
            JsonNode pv = policies.get(v.get("policyRef").asText());
            RoutingPolicyBundle bundle = JSON.treeToValue(pv.get("bundle"), RoutingPolicyBundle.class);
            Instant at = Instant.parse(v.get("evaluatedAt").asText());
            assertThat(bundle.inEffectAt(at)).as(name).isEqualTo(v.get("inEffect").asBoolean());

            ResolverVerifier verifier = new ResolverVerifier(List.of(), 1, trustedKeys(pv.get("trustedKeys")),
                    pv.get("threshold").asInt(), Clock.fixed(at, ZoneOffset.UTC));
            if (v.get("inEffect").asBoolean()) {
                verifier.verifyPolicy(bundle);
            } else {
                assertThatThrownBy(() -> verifier.verifyPolicy(bundle)).as(name)
                        .isInstanceOf(RoutingPolicyVerificationException.class);
            }
        }
    }

    @Test
    void everyWindowVectorFollowsTheWindowRule() throws Exception {
        for (JsonNode v : vectors().get("windows")) {
            RoutingPolicyBundle bounds = new RoutingPolicyBundle(RoutingPolicyBundle.SCHEMA_VERSION, "window", 1,
                    Instant.EPOCH, instant(v, "notBefore"), instant(v, "expiresAt"), List.of(), List.of(), null,
                    List.of(), List.of());
            assertThat(bounds.inEffectAt(Instant.parse(v.get("evaluatedAt").asText()))).as(v.get("name").asText())
                    .isEqualTo(v.get("inEffect").asBoolean());
        }
    }

    private static Instant instant(JsonNode n, String field) {
        String value = text(n, field);
        return value == null ? null : Instant.parse(value);
    }

    @Test
    void everyPlacementVectorReproducesTheReferenceDecision() throws Exception {
        JsonNode root = vectors();
        Map<String, JsonNode> rosters = byRef(root.get("rosters"));
        Map<String, JsonNode> policies = byRef(root.get("policies"));
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
            Map<String, String> attributes = new TreeMap<>();
            c.path("attributes").properties().forEach(e -> attributes.put(e.getKey(), e.getValue().asText()));
            PlacementContext ctx = new PlacementContext(c.get("phone").asText(), text(c, "country"), text(c, "mccmnc"),
                    text(c, "carrier"), text(c, "regionHint"), affiliations, attributes, false);

            Clock at = Clock.fixed(Instant.parse(v.get("evaluatedAt").asText()), ZoneOffset.UTC);
            ResolverVerifier verifier = new ResolverVerifier(trustedKeys(rv.get("trustedKeys")),
                    rv.get("threshold").asInt(), policyKeys, 1, at);
            PlacementDecision d = verifier.reproduceNewAccountDecision(ctx, roster, form(rv), policy);
            assertThat(d.homeserver().id()).as(name).isEqualTo(v.get("expectedHomeserverId").asText());
            assertThat(d.rule()).as(name).isEqualTo(v.get("expectedRule").asText());
            assertThat(d.ruleId()).as(name).isEqualTo(v.get("expectedRuleId").asText());
            assertThat(policy != null && verifier.unsignedRuleOutranks(ctx, policy, d)).as(name)
                    .isEqualTo(v.get("unsignedRuleAbove").asBoolean());
            if (v.has("fallback")) {
                JsonNode f = v.get("fallback");
                PlacementContext placed = ctx.withoutUnverifiedClaims();
                assertThat(placed.canonicalRoutingKey()).as(name).isEqualTo(f.get("routingKeyUtf8").asText());
                List<Homeserver> candidates = roster.activeEntries().stream().map(RosterEntry::homeserver)
                        .filter(Homeserver::acceptsNew).sorted(Comparator.comparing(Homeserver::id)).toList();
                assertThat(WeightedFallbackRule.stableHash(placed, roster.version(), candidates)).as(name)
                        .isEqualTo(f.get("stableHash").asInt());
            }
        }
    }

    @Test
    void everyResolveAnswerVectorLocatesTheExpectedEntry() throws Exception {
        JsonNode root = vectors();
        Map<String, JsonNode> rosters = byRef(root.get("rosters"));
        for (JsonNode v : root.get("resolveAnswers")) {
            String name = v.get("name").asText();
            SignedRoster roster = JSON.treeToValue(rosters.get(v.get("rosterRef").asText()).get("roster"),
                    SignedRoster.class);
            JsonNode a = v.get("answer");
            ResolverVerifier.Located located = ResolverVerifier.locate(a.get("serverName").asText(),
                    a.get("baseUrl").asText(), text(a, "masIssuer"), roster);
            assertThat(located.match().name()).as(name).isEqualTo(v.get("expected").asText());
            assertThat(located.entry() == null ? null : located.entry().homeserver().id()).as(name)
                    .isEqualTo(text(v, "expectedEntryId"));
        }
    }
}
