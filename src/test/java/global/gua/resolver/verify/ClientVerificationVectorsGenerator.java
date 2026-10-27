package global.gua.resolver.verify;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.crypto.Rfc8032Keys;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.placement.rules.WeightedFallbackRule;
import global.gua.resolver.policy.CanonicalDelegatedRules;
import global.gua.resolver.policy.CanonicalRoutingPolicy;
import global.gua.resolver.policy.DelegationZone;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicyRule;
import global.gua.resolver.policy.RoutingPolicySigner;
import global.gua.resolver.policy.RoutingPolicyVerifier;
import global.gua.resolver.roster.CanonicalMemberEntry;
import global.gua.resolver.roster.CanonicalRoster;
import global.gua.resolver.roster.MemberAttestation;
import global.gua.resolver.roster.MemberEntrySigner;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.SignedRoster;

/**
 * Regenerates docs/specs/gua-client-verification-v1-vectors.json, the byte-for-byte contract a platform
 * verifier (web, iOS, Android) checks itself against. Run with {@code ./gradlew clientVerificationVectors}.
 * {@code ClientVerificationVectorsTest} reproduces every value in the committed file with the production
 * code, so a diff in that file is a wire-contract change. Keys are RFC 8032 section 7.1 test constants.
 */
public final class ClientVerificationVectorsGenerator {

    static final Path OUT = Path.of("docs/specs/gua-client-verification-v1-vectors.json");
    static final Path PROD_SNAPSHOT = Path.of("src/test/resources/vectors/prod-roster-2026-10-27.json");
    /** The production authority key, published out of band. The snapshot is public data served at resolver.gua.global. */
    static final String PROD_AUTHORITY_KEY_ID = "gua-authority-prod";
    static final String PROD_AUTHORITY_PUBLIC_KEY = "MCowBQYDK2VwAyEAmrJntRXbxGkoPe92j1epyM3RBXcx4nmr2wIzL6eb0a0=";

    static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final HexFormat HEX = HexFormat.of();
    private static final Base64.Decoder B64 = Base64.getDecoder();

    record NamedKey(String id, String ref, String seedHex, String publicHex) {
        Ed25519.KeyPairB64 pair() {
            return Rfc8032Keys.pair(seedHex, publicHex);
        }
    }

    static final NamedKey AUTHORITY_A = new NamedKey("authority-a", "rfc8032-test1",
            Rfc8032Keys.TEST1_SEED_HEX, Rfc8032Keys.TEST1_PUBLIC_HEX);
    static final NamedKey AUTHORITY_B = new NamedKey("authority-b", "rfc8032-test2",
            Rfc8032Keys.TEST2_SEED_HEX, Rfc8032Keys.TEST2_PUBLIC_HEX);
    static final NamedKey GOVERNANCE_A = new NamedKey("governance-a", "rfc8032-test3",
            Rfc8032Keys.TEST3_SEED_HEX, Rfc8032Keys.TEST3_PUBLIC_HEX);
    static final NamedKey DELEGATE_SP = new NamedKey("delegate-sp", "rfc8032-test1024",
            Rfc8032Keys.TEST1024_SEED_HEX, Rfc8032Keys.TEST1024_PUBLIC_HEX);
    static final NamedKey MEMBER_BR = new NamedKey("hs-br-1", "rfc8032-test-sha-abc",
            Rfc8032Keys.TEST_SHA_ABC_SEED_HEX, Rfc8032Keys.TEST_SHA_ABC_PUBLIC_HEX);
    static final List<NamedKey> KEYS = List.of(AUTHORITY_A, AUTHORITY_B, GOVERNANCE_A, DELEGATE_SP, MEMBER_BR);

    static final Instant EVALUATED_AT = Instant.parse("2026-10-27T00:00:00Z");
    static final Instant ADMIT_BR = Instant.parse("2026-06-17T06:38:38.255492Z");
    static final Instant ADMIT_CA = Instant.parse("2026-07-20T04:18:34.332941Z");
    static final Instant ADMIT_OLD = Instant.parse("2026-02-01T00:00:00Z");

    /** Search groups whose UTF-16 code unit order differs from Unicode scalar order: pins Java's sort. */
    static final List<String> BR_GROUPS = List.of("b", "a", "Z", "é", "😀", "～");

    static final Homeserver HS_BR = new Homeserver("hs-br", "br.gua.test", "https://matrix.br.gua.test",
            "https://account.br.gua.test", "BR", 5, true, MEMBER_BR.pair().publicKeyB64(),
            Homeserver.SearchVisibility.GROUP, BR_GROUPS);
    static final Homeserver HS_CA = new Homeserver("hs-ca", "ca.gua.test", "https://matrix.ca.gua.test",
            "https://account.ca.gua.test", null, 3, true, AUTHORITY_B.pair().publicKeyB64(),
            Homeserver.SearchVisibility.SERVER, List.of());
    static final Homeserver HS_OLD = new Homeserver("hs-old", "old.gua.test", "https://matrix.old.gua.test",
            "https://account.old.gua.test", "BR", 2, true, "", Homeserver.SearchVisibility.GLOBAL, List.of());

    private ClientVerificationVectorsGenerator() {}

    public static void main(String[] args) throws Exception {
        selfCheckKeys();

        MemberAttestation brMember = brMember();
        RoutingPolicyBundle policy = policy(GOVERNANCE_A, true, true);
        List<LogEvent> events = events(brMember, policy);
        List<String> leafHashes = events.stream().map(LogEvent::leafHash).toList();

        SignedRoster r1 = signRoster(3, Instant.parse("2026-10-01T12:00:00.123456789Z"), checkpoint(leafHashes, 3),
                List.of(new RosterEntry(HS_BR, List.of(), ADMIT_BR, RosterEntry.Status.ACTIVE, brMember)), true,
                AUTHORITY_A);
        SignedRoster r2 = signRoster(7, Instant.parse("2026-10-02T00:00:00Z"), checkpoint(leafHashes, 7),
                List.of(new RosterEntry(HS_OLD, List.of(), ADMIT_OLD, RosterEntry.Status.SUSPENDED),
                        new RosterEntry(HS_BR, brClaims(), ADMIT_BR, RosterEntry.Status.ACTIVE, brMember),
                        new RosterEntry(HS_CA, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE)), true,
                AUTHORITY_A, AUTHORITY_B);
        SignedRoster r4 = signRoster(2, Instant.parse("2026-07-28T10:00:00.5Z"), checkpoint(leafHashes, 2),
                List.of(new RosterEntry(HS_BR, List.of(), ADMIT_BR, RosterEntry.Status.ACTIVE)), false, AUTHORITY_A);
        JsonNode prod = JSON.readTree(Files.readString(PROD_SNAPSHOT));
        SignedRoster r3 = JSON.treeToValue(prod, SignedRoster.class);

        ObjectNode root = JSON.createObjectNode();
        root.put("vectors", "gua-client-verification.v1");
        root.put("protocol", "docs/verification/gua-resolver-verification-protocol.md");
        ArrayNode notes = root.putArray("notes");
        notes.add("Keys are the RFC 8032 section 7.1 Ed25519 test constants: published values that must never sign anything real.");
        notes.add("Ed25519 is deterministic in the reference implementation, so every signature made with a test key is reproducible; a port that signs with a randomized implementation verifies instead of comparing bytes.");
        notes.add("canonicalUtf8 is the canonical bytes as a JSON string; the field separator of gua-roster.v1 is the control character U+001F.");
        notes.add("Instants are transported as ISO-8601 UTC with 0 to 9 fractional digits; the canonical bytes carry epoch milliseconds, truncated.");
        notes.add("A roster whose entries all lack searchVisibility is encoded with form legacy; one whose entries all carry it with form v1; a mix is refused.");
        notes.add("The legacy production snapshot is public data served at https://resolver.gua.global/roster on 2026-10-27, with the production authority public key published out of band.");
        notes.add("Expected placements come from the reference verifier over the verified roster and policy for a context that carries no verified claims; self-asserted affiliations never route.");

        root.set("keys", keys());
        root.set("instants", instants());
        root.set("rosters", rosters(r1, r2, r3, r4, prod));
        root.set("rosterRejections", rosterRejections(r1, r2, brMember));
        root.set("log", log(events, leafHashes));
        root.set("policies", policies(policy));
        root.set("policyRejections", policyRejections(policy));
        root.set("placements", placements(r1, r2, policy));
        root.set("resolveAnswers", resolveAnswers(r2, r3));

        Files.createDirectories(OUT.getParent());
        Files.writeString(OUT, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(root) + "\n");
        System.out.println("wrote " + OUT);
    }

    // ---- fixtures -------------------------------------------------------------------------------------------

    static void selfCheckKeys() {
        for (NamedKey k : KEYS) {
            Ed25519.KeyPairB64 pair = k.pair();
            String signature = Ed25519.sign(Ed25519.privateKey(pair.privateKeyB64()), new byte[] {1});
            if (!Ed25519.verify(Ed25519.publicKey(pair.publicKeyB64()), new byte[] {1}, signature)) {
                throw new IllegalStateException("public key does not match the seed for " + k.ref());
            }
        }
    }

    static MemberAttestation brMember() {
        MemberAttestation unsigned = new MemberAttestation(CanonicalMemberEntry.SCHEMA, CanonicalMemberEntry.ALG,
                MEMBER_BR.id(), 1, Instant.parse("2026-09-01T00:00:00Z"), Instant.parse("2027-09-01T00:00:00Z"),
                List.of());
        return MemberEntrySigner.sign(HS_BR, unsigned, MEMBER_BR.id(), MEMBER_BR.pair().privateKeyB64());
    }

    static List<ClaimPredicate> brClaims() {
        return List.of(
                new ClaimPredicate("BR", "72411", "Vivo", List.of("+5519", "+5511"), null, Map.of(), null, 10),
                new ClaimPredicate(null, null, null, null, "usp.br",
                        new TreeMap<>(Map.of("hd", "usp.br", "email_domain", "usp.br")), null, 5));
    }

    static SignedRoster signRoster(long version, Instant issuedAt, SignedRoster.LogCheckpoint checkpoint,
                                   List<RosterEntry> entries, boolean currentForm, NamedKey... signers) {
        byte[] canonical = currentForm
                ? CanonicalRoster.bytes(version, issuedAt.toEpochMilli(), checkpoint, entries)
                : CanonicalRoster.legacyBytes(version, issuedAt.toEpochMilli(), checkpoint, entries);
        List<SignedRoster.AuthoritySignature> signatures = new ArrayList<>();
        for (NamedKey k : signers) {
            signatures.add(new SignedRoster.AuthoritySignature(k.id(),
                    Ed25519.sign(Ed25519.privateKey(k.pair().privateKeyB64()), canonical)));
        }
        return new SignedRoster(version, issuedAt, entries, checkpoint, signatures);
    }

    static SignedRoster withSignatures(SignedRoster r, List<SignedRoster.AuthoritySignature> signatures) {
        return new SignedRoster(r.version(), r.issuedAt(), r.entries(), r.logCheckpoint(), signatures);
    }

    static SignedRoster withEntries(SignedRoster r, List<RosterEntry> entries) {
        return new SignedRoster(r.version(), r.issuedAt(), entries, r.logCheckpoint(), r.authoritySignatures());
    }

    static RoutingPolicyBundle policy(NamedKey authority, boolean signSp, boolean signEdu) {
        Instant notBefore = Instant.parse("2026-01-01T00:00:00Z");
        Instant expiresAt = Instant.parse("2030-01-01T00:00:00Z");
        List<DelegationZone> zones = List.of(
                new DelegationZone("sp-zone", DelegationZone.ScopeType.PHONE_PREFIX, "+55119", "carrier:vivo",
                        DELEGATE_SP.id(), DELEGATE_SP.pair().publicKeyB64(), List.of("hs-br"), notBefore, expiresAt),
                new DelegationZone("edu-zone", DelegationZone.ScopeType.INSTITUTION_DOMAIN, "usp.br",
                        "institution:usp", DELEGATE_SP.id(), DELEGATE_SP.pair().publicKeyB64(), List.of("hs-br"),
                        notBefore, expiresAt),
                new DelegationZone("na-zone", DelegationZone.ScopeType.PHONE_PREFIX, "+1", "carrier:na",
                        "delegate-na", AUTHORITY_B.pair().publicKeyB64(), List.of("hs-ca"), notBefore, expiresAt));
        List<RoutingPolicyRule> rules = List.of(
                new RoutingPolicyRule("r-sp", 10, RoutingPolicyRule.MatchType.PHONE_PREFIX, "+551198", null, null,
                        "hs-br", "sp-zone", "carrier route", RoutingPolicyRule.AssignmentPolicy.PORTABLE, true),
                new RoutingPolicyRule("r-usp", 5, RoutingPolicyRule.MatchType.INSTITUTION_DOMAIN, "usp.br", null,
                        null, "hs-br", "edu-zone", "institution route",
                        RoutingPolicyRule.AssignmentPolicy.REQUIRES_CONFIRMATION, true),
                new RoutingPolicyRule("r-disabled", 1, RoutingPolicyRule.MatchType.PHONE_PREFIX, "+55", null, null,
                        "hs-ca", "sp-zone", "disabled rule", null, false),
                new RoutingPolicyRule("r-na", 2, RoutingPolicyRule.MatchType.PHONE_PREFIX, "+1", null, null,
                        "hs-ca", "na-zone", null, RoutingPolicyRule.AssignmentPolicy.PORTABLE, null));
        RoutingPolicyBundle unsigned = new RoutingPolicyBundle(RoutingPolicyBundle.SCHEMA_VERSION, "br-policy", 3,
                Instant.parse("2026-09-15T08:30:00.25Z"), notBefore, expiresAt, zones, rules,
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true), List.of(), List.of());
        RoutingPolicyBundle signed = withPolicySignatures(unsigned, List.of(new RoutingPolicyBundle.PolicySignature(
                authority.id(), Ed25519.sign(Ed25519.privateKey(authority.pair().privateKeyB64()),
                        CanonicalRoutingPolicy.bytes(unsigned)))));
        if (signSp) {
            signed = RoutingPolicySigner.signZone(signed, "sp-zone", DELEGATE_SP.id(), DELEGATE_SP.pair().privateKeyB64());
        }
        if (signEdu) {
            signed = RoutingPolicySigner.signZone(signed, "edu-zone", DELEGATE_SP.id(), DELEGATE_SP.pair().privateKeyB64());
        }
        return signed;
    }

    static RoutingPolicyBundle withPolicySignatures(RoutingPolicyBundle b,
                                                    List<RoutingPolicyBundle.PolicySignature> signatures) {
        return new RoutingPolicyBundle(b.schemaVersion(), b.policyId(), b.version(), b.issuedAt(), b.notBefore(),
                b.expiresAt(), b.delegationZones(), b.rules(), b.fallback(), signatures, b.delegateSignatures());
    }

    static RoutingPolicyBundle withRules(RoutingPolicyBundle b, List<RoutingPolicyRule> rules) {
        return new RoutingPolicyBundle(b.schemaVersion(), b.policyId(), b.version(), b.issuedAt(), b.notBefore(),
                b.expiresAt(), b.delegationZones(), rules, b.fallback(), b.signatures(), b.delegateSignatures());
    }

    record LogEvent(long index, String type, String homeserverId, String payloadHash, Instant recordedAt) {
        String leafData() {
            return index + "|" + type + "|" + (homeserverId == null ? "" : homeserverId) + "|" + payloadHash
                    + "|" + recordedAt.toEpochMilli();
        }

        String leafHash() {
            return MerkleTree.leafHash(leafData().getBytes(StandardCharsets.UTF_8));
        }
    }

    static List<LogEvent> events(MemberAttestation brMember, RoutingPolicyBundle policy) {
        return List.of(
                new LogEvent(0, "ADMIT", "hs-br", MerkleTree.sha256Hex("admit:hs-br"), ADMIT_BR),
                new LogEvent(1, "ADMIT", "hs-ca", MerkleTree.sha256Hex("admit:hs-ca"), ADMIT_CA),
                new LogEvent(2, "MEMBER_ATTEST", "hs-br", CanonicalMemberEntry.hash(HS_BR, brMember),
                        Instant.parse("2026-09-01T00:00:00.000001Z")),
                new LogEvent(3, "POLICY_PUBLISH", "br-policy:v3",
                        MerkleTree.sha256Hex(CanonicalRoutingPolicy.bytes(policy)),
                        Instant.parse("2026-09-15T08:31:00.123456Z")),
                new LogEvent(4, "ADMIT", "hs-old", MerkleTree.sha256Hex("admit:hs-old"), ADMIT_OLD),
                new LogEvent(5, "SUSPENDED", "hs-old", MerkleTree.sha256Hex("suspend:hs-old"),
                        Instant.parse("2026-09-20T12:00:00Z")),
                new LogEvent(6, "DIRECTORY_CHECKPOINT", null, MerkleTree.sha256Hex("directory:1"),
                        Instant.parse("2026-10-01T11:59:59.999999999Z")));
    }

    static SignedRoster.LogCheckpoint checkpoint(List<String> leafHashes, int size) {
        return new SignedRoster.LogCheckpoint(MerkleTree.root(leafHashes.subList(0, size)), size);
    }

    static ResolverProperties.TrustedKey trusted(String id, String publicKeyB64) {
        ResolverProperties.TrustedKey k = new ResolverProperties.TrustedKey();
        k.setId(id);
        k.setPublicKey(publicKeyB64);
        return k;
    }

    static List<ResolverProperties.TrustedKey> trusted(List<NamedKey> keys) {
        return keys.stream().map(k -> trusted(k.id(), k.pair().publicKeyB64())).toList();
    }

    static RoutingPolicyVerifier policyVerifier(List<NamedKey> keys, int threshold) {
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setRequireSignatures(true);
        props.getPolicy().setSignatureThreshold(threshold);
        props.getPolicy().setTrustedKeys(trusted(keys));
        return new RoutingPolicyVerifier(props);
    }

    // ---- sections -------------------------------------------------------------------------------------------

    static ObjectNode keys() {
        ObjectNode keys = JSON.createObjectNode();
        for (NamedKey k : KEYS) {
            ObjectNode n = keys.putObject(k.ref());
            n.put("usedAsKeyId", k.id());
            n.put("seedHex", k.seedHex());
            n.put("publicKeyHex", k.publicHex());
            n.put("publicKeySpkiB64", k.pair().publicKeyB64());
            n.put("privateKeyPkcs8B64", k.pair().privateKeyB64());
        }
        ObjectNode prod = keys.putObject(PROD_AUTHORITY_KEY_ID);
        prod.put("usedAsKeyId", PROD_AUTHORITY_KEY_ID);
        prod.put("publicKeySpkiB64", PROD_AUTHORITY_PUBLIC_KEY);
        prod.put("publicKeyHex", HEX.formatHex(B64.decode(PROD_AUTHORITY_PUBLIC_KEY), 12, 44));
        prod.put("note", "production authority key; no private half here, signatures are verified only");
        return keys;
    }

    static ArrayNode instants() {
        ArrayNode out = JSON.createArrayNode();
        for (String iso : List.of("2026-10-13T11:45:26.302491581Z", "2026-08-01T01:25:10.023082Z",
                "2026-10-02T00:00:00Z", "2026-10-01T12:00:00.1Z", "2026-07-28T10:00:00.5Z",
                "2026-10-01T11:59:59.999999999Z", "1970-01-01T00:00:00Z", "2026-06-17T06:38:38.231502Z")) {
            ObjectNode n = out.addObject();
            n.put("iso", iso);
            n.put("epochMs", Long.toString(Instant.parse(iso).toEpochMilli()));
        }
        return out;
    }

    static ObjectNode rosterVector(String name, String form, SignedRoster roster, JsonNode rosterJson,
                                   List<ResolverProperties.TrustedKey> trustedKeys, int threshold,
                                   Map<String, String> signatureKeyRefs) {
        byte[] canonical = "legacy".equals(form) ? CanonicalRoster.legacyBytes(roster) : CanonicalRoster.bytes(roster);
        int valid = countValid(canonical, roster.authoritySignatures(), trustedKeys);
        ObjectNode v = JSON.createObjectNode();
        v.put("name", name);
        v.put("form", form);
        v.set("roster", rosterJson);
        v.put("canonicalUtf8", new String(canonical, StandardCharsets.UTF_8));
        v.put("canonicalHex", HEX.formatHex(canonical));
        v.put("sha256Hex", MerkleTree.sha256Hex(canonical));
        ArrayNode tk = v.putArray("trustedKeys");
        for (ResolverProperties.TrustedKey k : trustedKeys) {
            tk.addObject().put("id", k.getId()).put("publicKeySpkiB64", k.getPublicKey());
        }
        v.put("threshold", threshold);
        v.put("validSignatures", valid);
        v.put("verified", valid >= threshold);
        ObjectNode refs = v.putObject("signatureKeyRefs");
        signatureKeyRefs.forEach(refs::put);
        return v;
    }

    static int countValid(byte[] canonical, List<SignedRoster.AuthoritySignature> signatures,
                          List<ResolverProperties.TrustedKey> trustedKeys) {
        TreeSet<String> counted = new TreeSet<>();
        for (SignedRoster.AuthoritySignature s : signatures) {
            trustedKeys.stream().filter(k -> k.getId().equals(s.authorityKeyId())).findFirst().ifPresent(k -> {
                if (!counted.contains(k.getId())
                        && Ed25519.verify(Ed25519.publicKey(k.getPublicKey()), canonical, s.signatureB64())) {
                    counted.add(k.getId());
                }
            });
        }
        return counted.size();
    }

    static JsonNode stripSearchFields(SignedRoster roster) {
        ObjectNode tree = JSON.valueToTree(roster);
        for (JsonNode entry : tree.get("entries")) {
            ((ObjectNode) entry.get("homeserver")).remove("searchVisibility");
            ((ObjectNode) entry.get("homeserver")).remove("searchGroups");
        }
        return tree;
    }

    static ArrayNode rosters(SignedRoster r1, SignedRoster r2, SignedRoster r3, SignedRoster r4, JsonNode prodJson) {
        ArrayNode out = JSON.createArrayNode();
        out.add(rosterVector("one homeserver with a member attestation, threshold 1", "v1", r1,
                JSON.valueToTree(r1), trusted(List.of(AUTHORITY_A)), 1, Map.of(AUTHORITY_A.id(), AUTHORITY_A.ref())));
        out.add(rosterVector("three homeservers, claims, group visibility, a suspended entry, threshold 2 of 2",
                "v1", r2, JSON.valueToTree(r2), trusted(List.of(AUTHORITY_A, AUTHORITY_B)), 2,
                new TreeMap<>(Map.of(AUTHORITY_A.id(), AUTHORITY_A.ref(), AUTHORITY_B.id(), AUTHORITY_B.ref()))));
        out.add(rosterVector("legacy form: entries carry no search fields", "legacy", r4, stripSearchFields(r4),
                trusted(List.of(AUTHORITY_A)), 1, Map.of(AUTHORITY_A.id(), AUTHORITY_A.ref())));
        out.add(rosterVector("legacy form: production snapshot 2026-10-27", "legacy", r3, prodJson,
                List.of(trusted(PROD_AUTHORITY_KEY_ID, PROD_AUTHORITY_PUBLIC_KEY)), 1, Map.of()));
        return out;
    }

    static ArrayNode rosterRejections(SignedRoster r1, SignedRoster r2, MemberAttestation brMember) {
        ArrayNode out = JSON.createArrayNode();

        Homeserver evil = new Homeserver(HS_BR.id(), HS_BR.serverName(), "https://matrix.evil.test",
                HS_BR.masIssuer(), HS_BR.region(), HS_BR.weight(), HS_BR.acceptsNew(), HS_BR.signingKey(),
                HS_BR.searchVisibility(), HS_BR.searchGroups());
        out.add(rejection("tampered baseUrl under the original signature", "v1",
                withEntries(r1, List.of(new RosterEntry(evil, List.of(), ADMIT_BR, RosterEntry.Status.ACTIVE, brMember))),
                trusted(List.of(AUTHORITY_A)), 1, "the canonical bytes changed, the signature no longer verifies"));

        SignedRoster signedByB = signRoster(r1.version(), r1.issuedAt(), r1.logCheckpoint(), r1.entries(), true, AUTHORITY_B);
        out.add(rejection("signed by a key the client does not trust", "v1", signedByB,
                trusted(List.of(AUTHORITY_A)), 1, "authority-b is not in the trusted key set, zero votes"));

        SignedRoster aOnly = signRoster(r2.version(), r2.issuedAt(), r2.logCheckpoint(), r2.entries(), true, AUTHORITY_A);
        out.add(rejection("one of two required signatures", "v1", aOnly, trusted(List.of(AUTHORITY_A, AUTHORITY_B)),
                2, "one valid vote, threshold 2"));

        List<SignedRoster.AuthoritySignature> twice = new ArrayList<>(aOnly.authoritySignatures());
        twice.add(aOnly.authoritySignatures().get(0));
        out.add(rejection("the same key listed twice counts once", "v1", withSignatures(aOnly, twice),
                trusted(List.of(AUTHORITY_A, AUTHORITY_B)), 2, "duplicate key id, one vote, threshold 2"));

        out.add(rejection("legacy bytes offered for a roster whose entries carry searchVisibility", "legacy", r1,
                trusted(List.of(AUTHORITY_A)), 1, "the form follows the served JSON, the signature covers the v1 bytes"));

        ObjectNode mixed = JSON.valueToTree(r2);
        ((ObjectNode) mixed.get("entries").get(1).get("homeserver")).remove("searchVisibility");
        ((ObjectNode) mixed.get("entries").get(1).get("homeserver")).remove("searchGroups");
        ObjectNode m = out.addObject();
        m.put("name", "mixed field presence is refused before any signature check");
        m.put("form", "mixed");
        m.set("roster", mixed);
        m.put("clientOnly", true);
        m.put("reason", "one entry has searchVisibility and another has not; a verifier does not guess the form");
        return out;
    }

    static ObjectNode rejection(String name, String form, SignedRoster roster,
                                List<ResolverProperties.TrustedKey> trustedKeys, int threshold, String reason) {
        ObjectNode v = rosterVector(name, form, roster, JSON.valueToTree(roster), trustedKeys, threshold, Map.of());
        v.put("reason", reason);
        v.remove("signatureKeyRefs");
        if (v.get("verified").asBoolean()) {
            throw new IllegalStateException("rejection vector verifies: " + name);
        }
        return v;
    }

    static ObjectNode log(List<LogEvent> events, List<String> leafHashes) {
        ObjectNode log = JSON.createObjectNode();
        log.put("leafData", "index|type|homeserverId or empty|payloadHash|recordedAt as epoch milliseconds");
        log.put("hashing", "RFC 6962: leaf = SHA-256(0x00 || data), node = SHA-256(0x01 || left || right), empty tree = SHA-256 of nothing");
        ArrayNode ev = log.putArray("events");
        for (LogEvent e : events) {
            ObjectNode n = ev.addObject();
            n.put("index", e.index());
            n.put("type", e.type());
            if (e.homeserverId() == null) {
                n.putNull("homeserverId");
            } else {
                n.put("homeserverId", e.homeserverId());
            }
            n.put("payloadHash", e.payloadHash());
            n.put("recordedAt", e.recordedAt().toString());
            n.put("leafDataUtf8", e.leafData());
            n.put("leafHashHex", e.leafHash());
        }
        ArrayNode roots = log.putArray("roots");
        for (int size = 0; size <= events.size(); size++) {
            roots.addObject().put("size", size).put("rootHex", MerkleTree.root(leafHashes.subList(0, size)));
        }
        ArrayNode proofs = log.putArray("consistencyProofs");
        int[][] pairs = {{0, 7}, {1, 2}, {1, 3}, {1, 7}, {2, 3}, {2, 5}, {3, 5}, {3, 7}, {4, 7}, {5, 7}, {6, 7}, {7, 7}};
        for (int[] p : pairs) {
            List<String> proof = MerkleTree.consistencyProof(leafHashes, p[0], p[1]);
            String oldRoot = MerkleTree.root(leafHashes.subList(0, p[0]));
            String newRoot = MerkleTree.root(leafHashes.subList(0, p[1]));
            if (!MerkleTree.verifyConsistency(p[0], p[1], oldRoot, newRoot, proof)) {
                throw new IllegalStateException("consistency proof does not verify for " + p[0] + "," + p[1]);
            }
            ObjectNode n = proofs.addObject();
            n.put("first", p[0]);
            n.put("second", p[1]);
            n.put("oldRootHex", oldRoot);
            n.put("newRootHex", newRoot);
            ArrayNode pr = n.putArray("proof");
            proof.forEach(pr::add);
            n.put("valid", true);
        }
        ArrayNode invalid = log.putArray("invalidConsistencyProofs");
        String root3 = MerkleTree.root(leafHashes.subList(0, 3));
        String root4 = MerkleTree.root(leafHashes.subList(0, 4));
        String root5 = MerkleTree.root(leafHashes.subList(0, 5));
        String root7 = MerkleTree.root(leafHashes.subList(0, 7));
        List<String> p37 = MerkleTree.consistencyProof(leafHashes, 3, 7);
        List<String> p25 = MerkleTree.consistencyProof(leafHashes, 2, 5);
        String tamperedRoot7 = root7.substring(0, 63) + (root7.endsWith("0") ? "1" : "0");
        invalidProof(invalid, "new root tampered", 3, 7, root3, tamperedRoot7, p37, "the recomputed new root differs");
        invalidProof(invalid, "pinned checkpoint is not an ancestor", 3, 7, root4, root7, p37, "the recomputed old root differs from the pinned one");
        invalidProof(invalid, "proof for another pair", 3, 5, root3, root5, p25, "a proof is bound to its sizes");
        invalidProof(invalid, "rollback: the served tree is smaller than the pinned one", 7, 3, root7, root3, List.of(), "second < first is a rollback and is refused without computing anything");
        invalidProof(invalid, "proof truncated", 3, 7, root3, root7, p37.subList(0, p37.size() - 1), "too few nodes");
        invalidProof(invalid, "equal sizes with a non-empty proof", 3, 3, root3, root3, p37, "equal sizes need equal roots and an empty proof");
        invalidProof(invalid, "equal sizes with different roots", 3, 3, root3, root4, List.of(), "same size, different history");
        return log;
    }

    static void invalidProof(ArrayNode out, String name, int first, int second, String oldRoot, String newRoot,
                             List<String> proof, String reason) {
        if (MerkleTree.verifyConsistency(first, second, oldRoot, newRoot, proof)) {
            throw new IllegalStateException("invalid proof vector verifies: " + name);
        }
        ObjectNode n = out.addObject();
        n.put("name", name);
        n.put("first", first);
        n.put("second", second);
        n.put("oldRootHex", oldRoot);
        n.put("newRootHex", newRoot);
        ArrayNode pr = n.putArray("proof");
        proof.forEach(pr::add);
        n.put("valid", false);
        n.put("reason", reason);
    }

    static ObjectNode policyVector(String name, RoutingPolicyBundle bundle, List<NamedKey> trustedKeys, int threshold) {
        byte[] canonical = CanonicalRoutingPolicy.bytes(bundle);
        RoutingPolicyVerifier verifier = policyVerifier(trustedKeys, threshold);
        ObjectNode v = JSON.createObjectNode();
        v.put("name", name);
        v.set("bundle", JSON.valueToTree(bundle));
        v.put("canonicalUtf8", new String(canonical, StandardCharsets.UTF_8));
        v.put("canonicalHex", HEX.formatHex(canonical));
        v.put("sha256Hex", MerkleTree.sha256Hex(canonical));
        ArrayNode zones = v.putArray("delegatedRules");
        for (DelegationZone z : bundle.delegationZones()) {
            byte[] delegated = CanonicalDelegatedRules.bytes(bundle.policyId(), bundle.version(), z.id(), bundle.rules());
            ObjectNode n = zones.addObject();
            n.put("zoneId", z.id());
            n.put("canonicalUtf8", new String(delegated, StandardCharsets.UTF_8));
            n.put("canonicalHex", HEX.formatHex(delegated));
        }
        ArrayNode tk = v.putArray("trustedKeys");
        for (NamedKey k : trustedKeys) {
            tk.addObject().put("id", k.id()).put("publicKeySpkiB64", k.pair().publicKeyB64()).put("keyRef", k.ref());
        }
        v.put("threshold", threshold);
        v.put("verified", verifier.isVerified(bundle));
        ArrayNode zonesOk = v.putArray("delegateVerifiedZones");
        new TreeSet<>(verifier.delegateVerifiedZones(bundle)).forEach(zonesOk::add);
        return v;
    }

    static ArrayNode policies(RoutingPolicyBundle policy) {
        ArrayNode out = JSON.createArrayNode();
        out.add(policyVector("governance-signed bundle, both delegated zones signed, one zone unsigned", policy,
                List.of(GOVERNANCE_A), 1));
        out.add(policyVector("delegate signature missing for sp-zone: the bundle verifies, its sp rules do not apply",
                policy(GOVERNANCE_A, false, true), List.of(GOVERNANCE_A), 1));
        return out;
    }

    static ArrayNode policyRejections(RoutingPolicyBundle policy) {
        ArrayNode out = JSON.createArrayNode();
        ObjectNode a = policyVector("signed by the operational authority key instead of a governance key",
                policy(AUTHORITY_A, true, true), List.of(GOVERNANCE_A), 1);
        a.put("reason", "a client has no fallback from policy keys to authority keys");
        out.add(a);
        List<RoutingPolicyRule> rules = new ArrayList<>(policy.rules());
        RoutingPolicyRule sp = rules.get(0);
        rules.set(0, new RoutingPolicyRule(sp.id(), sp.priority(), sp.matchType(), sp.matchValue(), sp.oidcIssuer(),
                sp.oidcClaim(), "hs-ca", sp.delegatedZoneId(), sp.reason(), sp.assignmentPolicy(), sp.enabled()));
        ObjectNode b = policyVector("tampered rule target under the original signatures", withRules(policy, rules),
                List.of(GOVERNANCE_A), 1);
        b.put("reason", "the canonical bytes changed");
        out.add(b);
        ObjectNode c = policyVector("no policy keys configured verifies nothing", policy, List.of(), 1);
        c.put("reason", "an empty trusted key set accepts no bundle");
        out.add(c);
        for (JsonNode n : out) {
            if (n.get("verified").asBoolean()) {
                throw new IllegalStateException("policy rejection verifies: " + n.get("name"));
            }
        }
        return out;
    }

    static ArrayNode placements(SignedRoster r1, SignedRoster r2, RoutingPolicyBundle policy) {
        ArrayNode out = JSON.createArrayNode();
        RoutingPolicyBundle spUnsigned = policy(GOVERNANCE_A, false, true);
        String policyRef = "br-policy v3";
        String spUnsignedRef = "br-policy v3 without the sp-zone delegate signature";

        out.add(placement("signed policy rule wins", "r2", r2, List.of(AUTHORITY_A, AUTHORITY_B), 2, policyRef, policy,
                ctx("+5511987654321", null, null, null)));
        out.add(placement("policy rule before a matching roster claim", "r2", r2, List.of(AUTHORITY_A, AUTHORITY_B), 2,
                policyRef, policy, ctx("+5511987654321", "BR", "72411", "Vivo")));
        out.add(placement("roster claim with carrier context", "r2", r2, List.of(AUTHORITY_A, AUTHORITY_B), 2,
                policyRef, policy, ctx("+5519991112222", "BR", "72411", "Vivo")));
        out.add(placement("claim needs the carrier context: phone alone falls through", "r2", r2,
                List.of(AUTHORITY_A, AUTHORITY_B), 2, policyRef, policy, ctx("+5519991112222", null, null, null)));
        out.add(placement("rule in a zone without a delegate signature is ignored", "r2", r2,
                List.of(AUTHORITY_A, AUTHORITY_B), 2, policyRef, policy, ctx("+14165550123", null, null, null)));
        out.add(placement("self-asserted affiliation never routes", "r2", r2, List.of(AUTHORITY_A, AUTHORITY_B), 2,
                policyRef, policy, new PlacementContext("+5521999990000", null, null, null, null, List.of("usp.br"),
                        Map.of("email_domain", "usp.br"), false)));
        out.add(placement("missing sp delegate signature: the prefix rule does not apply", "r2", r2,
                List.of(AUTHORITY_A, AUTHORITY_B), 2, spUnsignedRef, spUnsigned, ctx("+5511987654321", null, null, null)));
        out.add(placement("no policy: weighted fallback", "r2", r2, List.of(AUTHORITY_A, AUTHORITY_B), 2, null, null,
                ctx("+5511987654321", null, null, null)));
        out.add(placement("single candidate", "r1", r1, List.of(AUTHORITY_A), 1, null, null,
                ctx("+5511987654321", null, null, null)));
        for (int i = 0; i < 8; i++) {
            out.add(placement("weighted fallback sample " + i, "r2", r2, List.of(AUTHORITY_A, AUTHORITY_B), 2,
                    policyRef, policy, ctx("+552199000" + String.format("%04d", i * 1237), null, null, null)));
        }
        return out;
    }

    static PlacementContext ctx(String phone, String country, String mccmnc, String carrier) {
        return new PlacementContext(phone, country, mccmnc, carrier, null, List.of(), Map.of(), false);
    }

    static ObjectNode placement(String name, String rosterRef, SignedRoster roster, List<NamedKey> authority,
                                int threshold, String policyRef, RoutingPolicyBundle policy, PlacementContext ctx) {
        ResolverVerifier verifier = new ResolverVerifier(trusted(authority), threshold, trusted(List.of(GOVERNANCE_A)), 1);
        PlacementDecision d = verifier.reproduceNewAccountDecision(ctx, roster, policy);
        ObjectNode v = JSON.createObjectNode();
        v.put("name", name);
        v.put("rosterRef", rosterRef);
        if (policyRef == null) {
            v.putNull("policyRef");
        } else {
            v.put("policyRef", policyRef);
        }
        ObjectNode c = v.putObject("context");
        c.put("phone", ctx.e164Phone());
        putIfPresent(c, "country", ctx.country());
        putIfPresent(c, "mccmnc", ctx.mccmnc());
        putIfPresent(c, "carrier", ctx.carrier());
        if (ctx.affiliations() != null && !ctx.affiliations().isEmpty()) {
            ArrayNode a = c.putArray("affiliations");
            ctx.affiliations().forEach(a::add);
        }
        if (ctx.attributes() != null && !ctx.attributes().isEmpty()) {
            ObjectNode a = c.putObject("attributes");
            new TreeMap<>(ctx.attributes()).forEach(a::put);
        }
        v.put("evaluatedAt", EVALUATED_AT.toString());
        v.put("expectedHomeserverId", d.homeserver().id());
        v.put("expectedRule", d.rule());
        v.put("expectedRuleId", d.ruleId());
        if ("weighted-fallback".equals(d.ruleId())) {
            List<Homeserver> candidates = roster.activeEntries().stream().map(RosterEntry::homeserver)
                    .filter(Homeserver::acceptsNew).sorted(Comparator.comparing(Homeserver::id)).toList();
            ObjectNode f = v.putObject("fallback");
            f.put("routingKeyUtf8", ctx.canonicalRoutingKey());
            f.put("rosterVersion", roster.version());
            ArrayNode cands = f.putArray("candidates");
            for (Homeserver h : candidates) {
                cands.addObject().put("id", h.id()).put("weight", Math.max(0, h.weight()));
            }
            f.put("stableHash", WeightedFallbackRule.stableHash(ctx, roster.version(), candidates));
        }
        return v;
    }

    static void putIfPresent(ObjectNode n, String field, String value) {
        if (value != null) {
            n.put(field, value);
        }
    }

    static ArrayNode resolveAnswers(SignedRoster r2, SignedRoster prod) {
        ArrayNode out = JSON.createArrayNode();
        answer(out, "active entry, identical fields", "r2", r2, HS_BR.serverName(), HS_BR.baseUrl(), HS_BR.masIssuer());
        answer(out, "suspended entry", "r2", r2, HS_OLD.serverName(), HS_OLD.baseUrl(), HS_OLD.masIssuer());
        answer(out, "known server name, different base URL", "r2", r2, HS_BR.serverName(), "https://matrix.evil.test", HS_BR.masIssuer());
        answer(out, "known server name, different auth issuer", "r2", r2, HS_BR.serverName(), HS_BR.baseUrl(), "https://account.evil.test");
        answer(out, "unknown server name", "r2", r2, "nobody.gua.test", HS_BR.baseUrl(), HS_BR.masIssuer());
        Homeserver p = prod.entries().get(0).homeserver();
        answer(out, "production snapshot, identical fields", "prod-2026-10-27", prod, p.serverName(), p.baseUrl(), p.masIssuer());
        return out;
    }

    static void answer(ArrayNode out, String name, String rosterRef, SignedRoster roster, String serverName,
                       String baseUrl, String masIssuer) {
        ObjectNode n = out.addObject();
        n.put("name", name);
        n.put("rosterRef", rosterRef);
        ObjectNode a = n.putObject("answer");
        a.put("serverName", serverName);
        a.put("baseUrl", baseUrl);
        a.put("masIssuer", masIssuer);
        n.put("expected", ResolverVerifier.locate(serverName, baseUrl, masIssuer, roster).name());
    }
}
