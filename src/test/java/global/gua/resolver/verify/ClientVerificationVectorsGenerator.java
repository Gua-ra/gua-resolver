package global.gua.resolver.verify;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
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
import global.gua.resolver.roster.RosterForm;
import global.gua.resolver.roster.RosterVerifier;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;

/**
 * Regenerates docs/specs/gua-client-verification-v1-vectors.json, which the web, iOS and Android verifiers test
 * against. Run it with {@code ./gradlew clientVerificationVectors}. {@code ClientVerificationVectorsTest}
 * checks every value in the committed file against the production code, so a diff in that file changes what
 * the apps must accept.
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
    static final Homeserver HS_BR_RETIRED = new Homeserver("hs-br-retired", HS_BR.serverName(), HS_BR.baseUrl(),
            HS_BR.masIssuer(), "BR", 1, false, "", Homeserver.SearchVisibility.GLOBAL, List.of());
    static final Homeserver HS_CA_RETIRED = new Homeserver("hs-ca-retired", HS_CA.serverName(), HS_CA.baseUrl(),
            HS_CA.masIssuer(), null, 1, false, "", Homeserver.SearchVisibility.GLOBAL, List.of());
    static final Homeserver HS_CA_MOVED = new Homeserver("hs-ca-moved", HS_CA.serverName(),
            "https://matrix2.ca.gua.test", HS_CA.masIssuer(), null, 3, true, "", Homeserver.SearchVisibility.GLOBAL,
            List.of());
    static final Homeserver HS_NO_ISSUER = new Homeserver("hs-no-issuer", "plain.gua.test",
            "https://matrix.plain.gua.test", null, null, 1, true, "", Homeserver.SearchVisibility.GLOBAL, List.of());
    static final Homeserver HS_HEAVY_A = new Homeserver("hs-heavy-a", "heavy-a.gua.test",
            "https://matrix.heavy-a.gua.test", "https://account.heavy-a.gua.test", null, 2_000_000_000, true, "",
            Homeserver.SearchVisibility.GLOBAL, List.of());
    static final Homeserver HS_HEAVY_B = new Homeserver("hs-heavy-b", "heavy-b.gua.test",
            "https://matrix.heavy-b.gua.test", "https://account.heavy-b.gua.test", null, 2_000_000_000, true, "",
            Homeserver.SearchVisibility.GLOBAL, List.of());

    record RosterFixture(String ref, SignedRoster roster, List<NamedKey> trustedKeys, int threshold) {}

    record PolicyFixture(String ref, RoutingPolicyBundle bundle) {}

    private ClientVerificationVectorsGenerator() {}

    public static void main(String[] args) throws Exception {
        Files.createDirectories(OUT.getParent());
        Files.writeString(OUT, render());
        System.out.println("wrote " + OUT);
    }

    /** The vectors file exactly as it must be committed. */
    static String render() throws Exception {
        return JSON.writerWithDefaultPrettyPrinter().writeValueAsString(build()) + "\n";
    }

    static ObjectNode build() throws Exception {
        selfCheckKeys();

        MemberAttestation brMember = brMember();
        RoutingPolicyBundle policy = policy(GOVERNANCE_A, true, true);
        List<LogEvent> events = events(brMember, policy);
        List<String> leafHashes = events.stream().map(LogEvent::leafHash).toList();

        RosterFixture r1 = new RosterFixture("r1", signRoster(3, Instant.parse("2026-10-01T12:00:00.123456789Z"),
                checkpoint(leafHashes, 3),
                List.of(new RosterEntry(HS_BR, List.of(), ADMIT_BR, RosterEntry.Status.ACTIVE, brMember)),
                RosterForm.V1, AUTHORITY_A), List.of(AUTHORITY_A), 1);
        RosterFixture r2 = new RosterFixture("r2", signRoster(7, Instant.parse("2026-10-02T00:00:00Z"),
                checkpoint(leafHashes, 7),
                List.of(new RosterEntry(HS_OLD, List.of(), ADMIT_OLD, RosterEntry.Status.SUSPENDED),
                        new RosterEntry(HS_BR, brClaims(), ADMIT_BR, RosterEntry.Status.ACTIVE, brMember),
                        new RosterEntry(HS_CA, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE)),
                RosterForm.V1, AUTHORITY_A, AUTHORITY_B), List.of(AUTHORITY_A, AUTHORITY_B), 2);
        SignedRoster r4 = signRoster(2, Instant.parse("2026-07-28T10:00:00.5Z"), checkpoint(leafHashes, 2),
                List.of(new RosterEntry(HS_BR, List.of(), ADMIT_BR, RosterEntry.Status.ACTIVE)), RosterForm.LEGACY,
                AUTHORITY_A);
        JsonNode prodJson = JSON.readTree(Files.readString(PROD_SNAPSHOT));
        SignedRoster prod = JSON.treeToValue(prodJson, SignedRoster.class);
        RosterFixture r5 = new RosterFixture("r5", signRoster(7, Instant.parse("2026-10-03T00:00:00Z"),
                checkpoint(leafHashes, 7),
                List.of(new RosterEntry(HS_BR_RETIRED, List.of(), ADMIT_OLD, RosterEntry.Status.SUSPENDED),
                        new RosterEntry(HS_BR, List.of(), ADMIT_BR, RosterEntry.Status.ACTIVE),
                        new RosterEntry(HS_CA_RETIRED, List.of(), ADMIT_OLD, RosterEntry.Status.SUSPENDED),
                        new RosterEntry(HS_CA_MOVED, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE)),
                RosterForm.V1, AUTHORITY_A), List.of(AUTHORITY_A), 1);
        RosterFixture r6 = new RosterFixture("r6", signRoster(7, Instant.parse("2026-10-04T00:00:00Z"),
                checkpoint(leafHashes, 7),
                List.of(new RosterEntry(HS_HEAVY_A, List.of(), ADMIT_BR, RosterEntry.Status.ACTIVE),
                        new RosterEntry(HS_HEAVY_B, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE)),
                RosterForm.V1, AUTHORITY_A), List.of(AUTHORITY_A), 1);
        RosterFixture r7 = new RosterFixture("r7", signRoster(7, Instant.parse("2026-10-05T00:00:00Z"),
                checkpoint(leafHashes, 7),
                List.of(new RosterEntry(HS_NO_ISSUER, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE)),
                RosterForm.V1, AUTHORITY_A), List.of(AUTHORITY_A), 1);
        PolicyFixture brPolicy = new PolicyFixture("br-policy v3", policy);
        PolicyFixture spUnsigned = new PolicyFixture("br-policy v3 without the sp-zone delegate signature",
                policy(GOVERNANCE_A, false, true));

        ObjectNode root = JSON.createObjectNode();
        root.put("vectors", "gua-client-verification.v1");
        root.put("protocol", "docs/verification/gua-resolver-verification-protocol.md");
        ArrayNode notes = root.putArray("notes");
        notes.add("The test keys are the Ed25519 example keys from RFC 8032, section 7.1. They are public, so never use them outside tests.");
        notes.add("The signatures were made with deterministic Ed25519, so they can be reproduced exactly. Some libraries, Apple CryptoKit among them, randomize Ed25519 signatures. With those, verify the signatures here and do not compare their bytes.");
        notes.add("canonicalUtf8 is the exact byte string that gets signed, written as a JSON string, and canonicalHex is the same bytes in hex. gua-roster.v1 separates fields with the control character U+001F.");
        notes.add("Timestamps appear in JSON as ISO-8601 UTC strings with 0 to 9 fractional digits. The signed bytes carry them as epoch milliseconds. Digits past the millisecond are dropped, not rounded.");
        notes.add("Rosters come in two forms. If no entry has searchVisibility, verify the legacy bytes, which leave out the search fields. If every entry has it, verify the v1 bytes. If only some entries have it, refuse the roster.");
        notes.add("The production roster is a copy of https://resolver.gua.global/roster as served on 2026-10-27. It is signed with the production authority key listed under keys.");
        notes.add("Each expected placement is the homeserver the Java reference verifier chooses for a new account from the verified roster and policy. No context carries verified claims, so an affiliation the client states without proof never changes the result.");
        notes.add("Placements are evaluated at their evaluatedAt instant, not at the current time. Weights are summed in 64 bits, so weights whose total passes 2^31 do not wrap.");
        notes.add("A policy bundle or delegation zone is in effect from notBefore, inclusive, until expiresAt, exclusive. A missing bound leaves that side open, and so does a bound at 1970-01-01T00:00:00Z, because the signed bytes write both as 0. policyValidity checks a bundle at its edges and windows checks the rule itself.");
        notes.add("A resolve answer is located by the strongest match in the roster, whatever the entry order: an ACTIVE entry with the same serverName, baseUrl and masIssuer, then any entry with all three, then any entry with the serverName. Ties go to the entry served first. expectedEntryId names the entry that decided the match.");
        notes.add("In the signed roster bytes a null id, serverName, baseUrl or masIssuer is the text null. The other optional fields are empty.");
        notes.add("expectedOutcome is the outcome a client reports for a rejected roster or policy. A placement's unsignedRuleAbove says whether a matching rule in a zone without a valid delegate signature outranks the rule that decided, which makes the placement check indeterminate(unsigned_rule).");
        notes.add("policyLog cases check a served bundle, or a 404 when servedPolicy is null, against all events in log.events and the checkpoint given in each case.");
        notes.add("Consistency proofs are checked as RFC 9162 section 2.1.4.2 describes, including its rule that a proof fails when hashes remain after the path is complete.");
        notes.add("Vectors refer to rosters and policies by their ref field.");

        root.set("keys", keys());
        root.set("instants", instants());
        root.set("rosters", rosters(r1, r2, r4, prod, prodJson, r5, r6, r7));
        root.set("rosterRejections", rosterRejections(r1.roster(), r2.roster(), brMember));
        root.set("log", log(events, leafHashes));
        root.set("policies", policies(brPolicy, spUnsigned));
        root.set("policyRejections", policyRejections(policy));
        root.set("policyValidity", policyValidity(brPolicy));
        root.set("windows", windows());
        root.set("policyLog", policyLog(events, policy, withRules(policy, retargetedRules(policy))));
        root.set("placements", placements(r1, r2, r6, brPolicy, spUnsigned));
        root.set("resolveAnswers", resolveAnswers(r2.roster(), prod, r5.roster(), r7.roster()));
        return root;
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
                                   List<RosterEntry> entries, RosterForm form, NamedKey... signers) {
        byte[] canonical = CanonicalRoster.bytes(version, issuedAt.toEpochMilli(), checkpoint, entries, form);
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

    static RoutingPolicyBundle withVersion(RoutingPolicyBundle b, long version) {
        return new RoutingPolicyBundle(b.schemaVersion(), b.policyId(), version, b.issuedAt(), b.notBefore(),
                b.expiresAt(), b.delegationZones(), b.rules(), b.fallback(), b.signatures(), b.delegateSignatures());
    }

    static List<RoutingPolicyRule> retargetedRules(RoutingPolicyBundle policy) {
        List<RoutingPolicyRule> rules = new ArrayList<>(policy.rules());
        RoutingPolicyRule sp = rules.get(0);
        rules.set(0, new RoutingPolicyRule(sp.id(), sp.priority(), sp.matchType(), sp.matchValue(), sp.oidcIssuer(),
                sp.oidcClaim(), "hs-ca", sp.delegatedZoneId(), sp.reason(), sp.assignmentPolicy(), sp.enabled()));
        return rules;
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

        TransparencyLog.Event served() {
            return new TransparencyLog.Event(index, type, homeserverId, payloadHash, recordedAt.toString());
        }

        String leafHash() {
            return served().leafHash();
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
                        Instant.parse("2026-10-01T11:59:59.999999999Z")),
                new LogEvent(7, "POLICY_PUBLISH", "br-policy:v4",
                        MerkleTree.sha256Hex(CanonicalRoutingPolicy.bytes(withVersion(policy, 4))),
                        Instant.parse("2026-10-05T00:00:00Z")));
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

    static RosterVerifier rosterVerifier(List<ResolverProperties.TrustedKey> keys, int threshold) {
        ResolverProperties props = new ResolverProperties();
        props.getAuthority().setThreshold(threshold);
        props.getAuthority().setTrustedKeys(keys);
        return new RosterVerifier(props);
    }

    static ResolverVerifier verifierAt(Instant now, List<NamedKey> authority, int threshold) {
        return new ResolverVerifier(trusted(authority), threshold, trusted(List.of(GOVERNANCE_A)), 1,
                Clock.fixed(now, ZoneOffset.UTC));
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
        prod.put("note", "Production authority public key. This file holds no private key for it.");
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

    static ObjectNode rosterVector(String name, String ref, RosterForm form, SignedRoster roster, JsonNode rosterJson,
                                   List<ResolverProperties.TrustedKey> trustedKeys, int threshold,
                                   Map<String, String> signatureKeyRefs) {
        byte[] canonical = CanonicalRoster.bytes(roster, form);
        int valid = rosterVerifier(trustedKeys, threshold).countValidSignatures(roster, form);
        ObjectNode v = JSON.createObjectNode();
        v.put("name", name);
        if (ref != null) {
            v.put("ref", ref);
        }
        v.put("form", form.name().toLowerCase(Locale.ROOT));
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

    static Map<String, String> keyRefs(List<NamedKey> keys) {
        Map<String, String> refs = new TreeMap<>();
        keys.forEach(k -> refs.put(k.id(), k.ref()));
        return refs;
    }

    static JsonNode stripSearchFields(SignedRoster roster) {
        ObjectNode tree = JSON.valueToTree(roster);
        for (JsonNode entry : tree.get("entries")) {
            ((ObjectNode) entry.get("homeserver")).remove("searchVisibility");
            ((ObjectNode) entry.get("homeserver")).remove("searchGroups");
        }
        return tree;
    }

    static ObjectNode rosterVector(String name, RosterFixture f) {
        return rosterVector(name, f.ref(), RosterForm.V1, f.roster(), JSON.valueToTree(f.roster()),
                trusted(f.trustedKeys()), f.threshold(), keyRefs(f.trustedKeys()));
    }

    static ArrayNode rosters(RosterFixture r1, RosterFixture r2, SignedRoster r4, SignedRoster prod, JsonNode prodJson,
                             RosterFixture r5, RosterFixture r6, RosterFixture r7) {
        ArrayNode out = JSON.createArrayNode();
        out.add(rosterVector("one homeserver that signs its own entry; one authority signature required", r1));
        out.add(rosterVector("three homeservers with routing claims, group search visibility and one suspended entry;"
                + " two of two authority signatures required", r2));
        out.add(rosterVector("legacy form: no entry has search fields", "r4", RosterForm.LEGACY, r4,
                stripSearchFields(r4), trusted(List.of(AUTHORITY_A)), 1, keyRefs(List.of(AUTHORITY_A))));
        out.add(rosterVector("legacy form: the production roster of 2026-10-27", "prod-2026-10-27", RosterForm.LEGACY,
                prod, prodJson, List.of(trusted(PROD_AUTHORITY_KEY_ID, PROD_AUTHORITY_PUBLIC_KEY)), 1, Map.of()));
        out.add(rosterVector("two server names that each appear twice: a suspended entry served before an active one",
                r5));
        out.add(rosterVector("two homeservers whose weights add up past 2^31", r6));
        out.add(rosterVector("an entry without an auth issuer", r7));

        SignedRoster.AuthoritySignature bad = new SignedRoster.AuthoritySignature(AUTHORITY_A.id(),
                Ed25519.sign(Ed25519.privateKey(AUTHORITY_A.pair().privateKeyB64()), new byte[] {0}));
        SignedRoster badThenGood = withSignatures(r1.roster(),
                List.of(bad, r1.roster().authoritySignatures().get(0)));
        ObjectNode retried = rosterVector("an invalid signature from a key followed by a valid one from the same key",
                null, RosterForm.V1, badThenGood, JSON.valueToTree(badThenGood), trusted(List.of(AUTHORITY_A)), 1,
                Map.of());
        retried.put("reason", "A signature that fails does not use up its key, so the valid one still counts.");
        retried.remove("signatureKeyRefs");
        out.add(retried);
        return out;
    }

    static ArrayNode rosterRejections(SignedRoster r1, SignedRoster r2, MemberAttestation brMember) {
        ArrayNode out = JSON.createArrayNode();

        Homeserver evil = new Homeserver(HS_BR.id(), HS_BR.serverName(), "https://matrix.evil.test",
                HS_BR.masIssuer(), HS_BR.region(), HS_BR.weight(), HS_BR.acceptsNew(), HS_BR.signingKey(),
                HS_BR.searchVisibility(), HS_BR.searchGroups());
        out.add(rejection("baseUrl changed after signing", RosterForm.V1,
                withEntries(r1, List.of(new RosterEntry(evil, List.of(), ADMIT_BR, RosterEntry.Status.ACTIVE, brMember))),
                trusted(List.of(AUTHORITY_A)), 1, "The signed bytes changed, so the signature fails."));

        SignedRoster signedByB = signRoster(r1.version(), r1.issuedAt(), r1.logCheckpoint(), r1.entries(),
                RosterForm.V1, AUTHORITY_B);
        out.add(rejection("signed by a key the client does not trust", RosterForm.V1, signedByB,
                trusted(List.of(AUTHORITY_A)), 1,
                "Only authority-b signed and the client trusts only authority-a, so no signature counts."));

        SignedRoster aOnly = signRoster(r2.version(), r2.issuedAt(), r2.logCheckpoint(), r2.entries(),
                RosterForm.V1, AUTHORITY_A);
        out.add(rejection("one signature where two are required", RosterForm.V1, aOnly,
                trusted(List.of(AUTHORITY_A, AUTHORITY_B)), 2, "One valid signature, two required."));

        List<SignedRoster.AuthoritySignature> twice = new ArrayList<>(aOnly.authoritySignatures());
        twice.add(aOnly.authoritySignatures().get(0));
        out.add(rejection("the same signature listed twice", RosterForm.V1, withSignatures(aOnly, twice),
                trusted(List.of(AUTHORITY_A, AUTHORITY_B)), 2,
                "A key counts once however often it appears, so the second required signature is missing."));

        out.add(rejection("a v1 roster checked against its legacy bytes", RosterForm.LEGACY, r1,
                trusted(List.of(AUTHORITY_A)), 1, "The signature covers the v1 bytes, so the legacy bytes fail."
                        + " Check this vector with the form it names, not the form its JSON implies."));

        ObjectNode mixed = JSON.valueToTree(r2);
        ((ObjectNode) mixed.get("entries").get(1).get("homeserver")).remove("searchVisibility");
        ((ObjectNode) mixed.get("entries").get(1).get("homeserver")).remove("searchGroups");
        ObjectNode m = out.addObject();
        m.put("name", "some entries have searchVisibility and others do not");
        m.put("form", "mixed");
        m.set("roster", mixed);
        m.put("clientOnly", true);
        m.put("reason", "The form is ambiguous, so the roster is refused before any signature is checked.");
        m.put("expectedOutcome", "unverifiable(mixed_roster_form)");
        return out;
    }

    static ObjectNode rejection(String name, RosterForm form, SignedRoster roster,
                                List<ResolverProperties.TrustedKey> trustedKeys, int threshold, String reason) {
        ObjectNode v = rosterVector(name, null, form, roster, JSON.valueToTree(roster), trustedKeys, threshold,
                Map.of());
        v.put("reason", reason);
        v.put("expectedOutcome",
                new ResolverVerifier(trustedKeys, threshold, List.of(), 1).rosterSignatureOutcome(roster, form));
        v.remove("signatureKeyRefs");
        if (v.get("verified").asBoolean()) {
            throw new IllegalStateException("rejection vector verifies: " + name);
        }
        return v;
    }

    static ObjectNode log(List<LogEvent> events, List<String> leafHashes) {
        ObjectNode log = JSON.createObjectNode();
        log.put("leafData", "Each leaf is the UTF-8 string index|type|homeserverId|payloadHash|recordedAt. homeserverId holds the event subject, such as hs-br or br-policy:v3, and is empty when null. recordedAt is in epoch milliseconds.");
        log.put("hashing", "RFC 6962 hashing: a leaf is SHA-256(0x00 || data), an inner node is SHA-256(0x01 || left || right), and the root of the empty tree is the SHA-256 of zero bytes.");
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
        invalidProof(invalid, "the new root was changed", 3, 7, root3, tamperedRoot7, p37, "The proof leads to a different new root.");
        invalidProof(invalid, "the pinned root is not part of the new tree", 3, 7, root4, root7, p37, "The proof leads to a different old root than the one pinned.");
        invalidProof(invalid, "a proof made for other sizes", 3, 5, root3, root5, p25, "The proof was made for sizes 2 and 5, not 3 and 5.");
        invalidProof(invalid, "rollback: the served tree is smaller than the pinned one", 7, 3, root7, root3, List.of(), "A tree that shrank is a rollback. Refuse it without checking the proof.");
        invalidProof(invalid, "proof with its last hash removed", 3, 7, root3, root7, p37.subList(0, p37.size() - 1), "The proof is too short.");
        invalidProof(invalid, "equal sizes with a non-empty proof", 3, 3, root3, root3, p37, "Two trees of the same size need the same root and an empty proof.");
        invalidProof(invalid, "equal sizes with different roots", 3, 3, root3, root4, List.of(), "Same size, different root: the history was rewritten.");
        String root6 = MerkleTree.root(leafHashes.subList(0, 6));
        String filler = MerkleTree.sha256Hex("filler");
        String forgedRoot8 = nodeHashHex(MerkleTree.root(leafHashes.subList(0, 4)),
                nodeHashHex(leafHashes.get(4), nodeHashHex(leafHashes.get(5), filler)));
        invalidProof(invalid, "a proof with hashes left after the path ends", 6, 8, root6, forgedRoot8,
                List.of(leafHashes.get(5), filler, leafHashes.get(4), MerkleTree.root(leafHashes.subList(0, 4))),
                "RFC 9162 fails a proof once the path is complete and hashes remain. Without that rule this one proves a root no 8-leaf log has.");
        return log;
    }

    static String nodeHashHex(String leftHex, String rightHex) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update((byte) 0x01);
            digest.update(HEX.parseHex(leftHex));
            digest.update(HEX.parseHex(rightHex));
            return HEX.formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
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

    static ObjectNode policyVector(String name, String ref, RoutingPolicyBundle bundle, List<NamedKey> trustedKeys,
                                   int threshold) {
        byte[] canonical = CanonicalRoutingPolicy.bytes(bundle);
        RoutingPolicyVerifier verifier = RoutingPolicyVerifier.forKeys(trusted(trustedKeys), threshold);
        ObjectNode v = JSON.createObjectNode();
        v.put("name", name);
        if (ref != null) {
            v.put("ref", ref);
        }
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

    static ArrayNode policies(PolicyFixture policy, PolicyFixture spUnsigned) {
        ArrayNode out = JSON.createArrayNode();
        out.add(policyVector("signed by a policy key; two zones carry delegate signatures and one does not",
                policy.ref(), policy.bundle(), List.of(GOVERNANCE_A), 1));
        out.add(policyVector("no delegate signature for sp-zone: the bundle verifies but its sp-zone rules are ignored",
                spUnsigned.ref(), spUnsigned.bundle(), List.of(GOVERNANCE_A), 1));
        return out;
    }

    static ArrayNode policyRejections(RoutingPolicyBundle policy) {
        ArrayNode out = JSON.createArrayNode();
        ObjectNode a = policyVector("signed by the roster authority key, which is not a policy key", null,
                policy(AUTHORITY_A, true, true), List.of(GOVERNANCE_A), 1);
        a.put("reason", "Policies are checked against the policy keys only. The roster authority key does not count.");
        a.put("expectedOutcome", policySignatureOutcome(policy(AUTHORITY_A, true, true), List.of(GOVERNANCE_A)));
        out.add(a);
        RoutingPolicyBundle retargeted = withRules(policy, retargetedRules(policy));
        ObjectNode b = policyVector("a rule target changed after signing", null, retargeted, List.of(GOVERNANCE_A), 1);
        b.put("reason", "The signed bytes changed, so the signature fails.");
        b.put("expectedOutcome", policySignatureOutcome(retargeted, List.of(GOVERNANCE_A)));
        out.add(b);
        ObjectNode c = policyVector("no policy keys configured", null, policy, List.of(), 1);
        c.put("reason", "With no trusted policy keys, no bundle can verify.");
        c.put("expectedOutcome", policySignatureOutcome(policy, List.of()));
        out.add(c);
        for (JsonNode n : out) {
            if (n.get("verified").asBoolean()) {
                throw new IllegalStateException("policy rejection verifies: " + n.get("name"));
            }
        }
        return out;
    }

    static String policySignatureOutcome(RoutingPolicyBundle bundle, List<NamedKey> trustedKeys) {
        return new ResolverVerifier(List.of(), 1, trusted(trustedKeys), 1).policySignatureOutcome(bundle);
    }

    static ArrayNode policyLog(List<LogEvent> events, RoutingPolicyBundle policy, RoutingPolicyBundle unlogged) {
        List<String> leaves = events.stream().map(LogEvent::leafHash).toList();
        ArrayNode out = JSON.createArrayNode();
        logCase(out, "the served bundle is logged within the checkpoint", events, policy, 7, rootOf(leaves, 7));
        logCase(out, "the served bundle is logged only past the checkpoint", events, policy, 3, rootOf(leaves, 3));
        logCase(out, "a newer version of the served policy is logged", events, policy, 8, rootOf(leaves, 8));
        logCase(out, "the served bundle is not in the log", events, unlogged, 7, rootOf(leaves, 7));
        logCase(out, "no policy is served and none is logged", events, null, 3, rootOf(leaves, 3));
        logCase(out, "no policy is served although one is logged", events, null, 7, rootOf(leaves, 7));
        logCase(out, "the first leaves do not hash to the signed root", events, policy, 7, rootOf(leaves, 6));
        logCase(out, "no policy is served and the first leaves do not hash to the signed root", events, null, 3,
                rootOf(leaves, 2));
        logCase(out, "the checkpoint is larger than the log", events, null, 9, rootOf(leaves, 8));
        return out;
    }

    static String rootOf(List<String> leaves, int size) {
        return MerkleTree.root(leaves.subList(0, size));
    }

    static void logCase(ArrayNode out, String name, List<LogEvent> events, RoutingPolicyBundle served, int size,
                        String root) {
        String bundleHash = served == null ? null : MerkleTree.sha256Hex(CanonicalRoutingPolicy.bytes(served));
        ObjectNode n = out.addObject();
        n.put("name", name);
        if (served == null) {
            n.putNull("servedPolicy");
        } else {
            n.putObject("servedPolicy").put("policyId", served.policyId()).put("version", served.version())
                    .put("sha256Hex", bundleHash);
        }
        n.putObject("checkpoint").put("size", size).put("rootHex", root);
        n.put("expected", ResolverVerifier.policyLogOutcome(events.stream().map(LogEvent::served).toList(),
                new SignedRoster.LogCheckpoint(root, size), served));
    }

    static ArrayNode windows() {
        ArrayNode out = JSON.createArrayNode();
        Instant notBefore = Instant.parse("2026-01-01T00:00:00Z");
        Instant expiresAt = Instant.parse("2030-01-01T00:00:00Z");
        Instant inside = Instant.parse("2026-10-27T00:00:00Z");
        window(out, "inside both bounds", notBefore, expiresAt, inside);
        window(out, "no expiresAt", notBefore, null, Instant.parse("2040-01-01T00:00:00Z"));
        window(out, "an expiresAt at the epoch, which is signed as no expiresAt", notBefore, Instant.EPOCH, inside);
        window(out, "a notBefore at the epoch, which is signed as no notBefore", Instant.EPOCH, expiresAt, inside);
        window(out, "no bounds at all", null, null, inside);
        window(out, "after expiresAt", notBefore, expiresAt, Instant.parse("2031-01-01T00:00:00Z"));
        window(out, "before notBefore", notBefore, expiresAt, Instant.parse("2025-01-01T00:00:00Z"));
        return out;
    }

    static void window(ArrayNode out, String name, Instant notBefore, Instant expiresAt, Instant at) {
        RoutingPolicyBundle bounds = new RoutingPolicyBundle(RoutingPolicyBundle.SCHEMA_VERSION, "window", 1, at,
                notBefore, expiresAt, List.of(), List.of(), null, List.of(), List.of());
        ObjectNode n = out.addObject();
        n.put("name", name);
        putInstantOrNull(n, "notBefore", notBefore);
        putInstantOrNull(n, "expiresAt", expiresAt);
        n.put("evaluatedAt", at.toString());
        n.put("inEffect", bounds.inEffectAt(at));
    }

    static void putInstantOrNull(ObjectNode n, String field, Instant value) {
        if (value == null) {
            n.putNull(field);
        } else {
            n.put(field, value.toString());
        }
    }

    static ArrayNode policyValidity(PolicyFixture policy) {
        RoutingPolicyBundle bundle = policy.bundle();
        ArrayNode out = JSON.createArrayNode();
        validity(out, "1 ms before notBefore", policy, bundle.notBefore().minusMillis(1));
        validity(out, "at notBefore", policy, bundle.notBefore());
        validity(out, "1 ms before expiresAt", policy, bundle.expiresAt().minusMillis(1));
        validity(out, "at expiresAt", policy, bundle.expiresAt());
        return out;
    }

    static void validity(ArrayNode out, String name, PolicyFixture policy, Instant at) {
        ObjectNode n = out.addObject();
        n.put("name", name);
        n.put("policyRef", policy.ref());
        n.put("evaluatedAt", at.toString());
        n.put("inEffect", policy.bundle().inEffectAt(at));
    }

    static ArrayNode placements(RosterFixture r1, RosterFixture r2, RosterFixture r6, PolicyFixture policy,
                                PolicyFixture spUnsigned) {
        ArrayNode out = JSON.createArrayNode();
        out.add(placement("a signed policy rule decides", r2, policy, ctx("+5511987654321", null, null, null)));
        out.add(placement("a policy rule takes precedence over a matching roster claim", r2, policy,
                ctx("+5511987654321", "BR", "72411", "Vivo")));
        out.add(placement("a roster claim matches when the carrier is known", r2, policy,
                ctx("+5519991112222", "BR", "72411", "Vivo")));
        out.add(placement("without the carrier the claim does not match, so the fallback decides", r2, policy,
                ctx("+5519991112222", null, null, null)));
        out.add(placement("a rule in a zone without a delegate signature is ignored", r2, policy,
                ctx("+14165550123", null, null, null)));
        out.add(placement("an affiliation the client states without proof is ignored", r2, policy,
                new PlacementContext("+5521999990000", null, null, null, null, List.of("usp.br"),
                        Map.of("email_domain", "usp.br"), false)));
        out.add(placement("without the sp-zone delegate signature the prefix rule is ignored", r2, spUnsigned,
                ctx("+5511987654321", null, null, null)));
        out.add(placement("no policy: the weighted fallback decides", r2, null,
                ctx("+5511987654321", null, null, null)));
        out.add(placement("only one homeserver accepts new accounts", r1, null,
                ctx("+5511987654321", null, null, null)));
        for (int i = 0; i < 8; i++) {
            out.add(placement("weighted fallback sample " + i, r2, policy,
                    ctx("+552199000" + String.format("%04d", i * 1237), null, null, null)));
        }
        for (int i = 0; i < 4; i++) {
            out.add(placement("weights that add up past 2^31, sample " + i, r6, null,
                    ctx("+552199000" + String.format("%04d", i * 1237), null, null, null)));
        }
        return out;
    }

    static PlacementContext ctx(String phone, String country, String mccmnc, String carrier) {
        return new PlacementContext(phone, country, mccmnc, carrier, null, List.of(), Map.of(), false);
    }

    static ObjectNode placement(String name, RosterFixture rosterFixture, PolicyFixture policyFixture,
                                PlacementContext ctx) {
        SignedRoster roster = rosterFixture.roster();
        RoutingPolicyBundle policy = policyFixture == null ? null : policyFixture.bundle();
        ResolverVerifier verifier = verifierAt(EVALUATED_AT, rosterFixture.trustedKeys(), rosterFixture.threshold());
        PlacementDecision d = verifier.reproduceNewAccountDecision(ctx, roster, RosterForm.V1, policy);
        PlacementContext placed = ctx.withoutUnverifiedClaims();
        ObjectNode v = JSON.createObjectNode();
        v.put("name", name);
        v.put("rosterRef", rosterFixture.ref());
        if (policyFixture == null) {
            v.putNull("policyRef");
        } else {
            v.put("policyRef", policyFixture.ref());
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
        v.put("unsignedRuleAbove", policy != null && verifier.unsignedRuleOutranks(ctx, policy, d));
        if ("weighted-fallback".equals(d.ruleId())) {
            List<Homeserver> candidates = roster.activeEntries().stream().map(RosterEntry::homeserver)
                    .filter(Homeserver::acceptsNew).sorted(Comparator.comparing(Homeserver::id)).toList();
            ObjectNode f = v.putObject("fallback");
            f.put("routingKeyUtf8", placed.canonicalRoutingKey());
            f.put("rosterVersion", roster.version());
            ArrayNode cands = f.putArray("candidates");
            for (Homeserver h : candidates) {
                cands.addObject().put("id", h.id()).put("weight", Math.max(0, h.weight()));
            }
            f.put("stableHash", WeightedFallbackRule.stableHash(placed, roster.version(), candidates));
        }
        return v;
    }

    static void putIfPresent(ObjectNode n, String field, String value) {
        if (value != null) {
            n.put(field, value);
        }
    }

    static ArrayNode resolveAnswers(SignedRoster r2, SignedRoster prod, SignedRoster r5, SignedRoster r7) {
        ArrayNode out = JSON.createArrayNode();
        answer(out, "matches an active entry exactly", "r2", r2, HS_BR.serverName(), HS_BR.baseUrl(), HS_BR.masIssuer());
        answer(out, "matches a suspended entry", "r2", r2, HS_OLD.serverName(), HS_OLD.baseUrl(), HS_OLD.masIssuer());
        answer(out, "known server name, different base URL", "r2", r2, HS_BR.serverName(), "https://matrix.evil.test", HS_BR.masIssuer());
        answer(out, "known server name, different auth issuer", "r2", r2, HS_BR.serverName(), HS_BR.baseUrl(), "https://account.evil.test");
        answer(out, "unknown server name", "r2", r2, "nobody.gua.test", HS_BR.baseUrl(), HS_BR.masIssuer());
        Homeserver p = prod.entries().get(0).homeserver();
        answer(out, "matches the production entry exactly", "prod-2026-10-27", prod, p.serverName(), p.baseUrl(), p.masIssuer());
        answer(out, "an active entry wins over a suspended one served earlier", "r5", r5, HS_BR.serverName(),
                HS_BR.baseUrl(), HS_BR.masIssuer());
        answer(out, "a suspended entry with all three fields wins over an active one with another base URL", "r5",
                r5, HS_CA.serverName(), HS_CA.baseUrl(), HS_CA.masIssuer());
        answer(out, "with no entry matching all three fields, the first entry with the server name decides", "r5",
                r5, HS_CA.serverName(), "https://matrix.evil.test", HS_CA.masIssuer());
        answer(out, "an answer without an auth issuer matches an entry without one", "r7", r7,
                HS_NO_ISSUER.serverName(), HS_NO_ISSUER.baseUrl(), null);
        return out;
    }

    static void answer(ArrayNode out, String name, String rosterRef, SignedRoster roster, String serverName,
                       String baseUrl, String masIssuer) {
        ResolverVerifier.Located located = ResolverVerifier.locate(serverName, baseUrl, masIssuer, roster);
        ObjectNode n = out.addObject();
        n.put("name", name);
        n.put("rosterRef", rosterRef);
        ObjectNode a = n.putObject("answer");
        a.put("serverName", serverName);
        a.put("baseUrl", baseUrl);
        a.put("masIssuer", masIssuer);
        n.put("expected", located.match().name());
        if (located.entry() == null) {
            n.putNull("expectedEntryId");
        } else {
            n.put("expectedEntryId", located.entry().homeserver().id());
        }
    }
}
