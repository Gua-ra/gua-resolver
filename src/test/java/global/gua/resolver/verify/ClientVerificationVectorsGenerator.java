package global.gua.resolver.verify;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.TreeSet;

import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
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
 * {@code ./gradlew clientVerificationVectors} regenerates docs/specs/gua-client-verification-v1-vectors.json. The
 * web, iOS and Android verifiers test against that file, so a diff in it changes what the apps must accept.
 */
public final class ClientVerificationVectorsGenerator {

    static final Path OUT = Path.of("docs/specs/gua-client-verification-v1-vectors.json");
    static final Path PROD_SNAPSHOT = Path.of("src/test/resources/vectors/prod-roster-2026-10-27.json");
    static final String PROD_AUTHORITY_KEY_ID = "gua-authority-prod";
    static final String PROD_AUTHORITY_PUBLIC_KEY = "MCowBQYDK2VwAyEAmrJntRXbxGkoPe92j1epyM3RBXcx4nmr2wIzL6eb0a0=";

    static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final HexFormat HEX = HexFormat.of();
    private static final Base64.Decoder B64 = Base64.getDecoder();
    private static final Base64.Encoder B64E = Base64.getEncoder();

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
    static final Homeserver HS_HEAVY_A = fallbackHomeserver("hs-heavy-a", 2_000_000_000, true);
    static final Homeserver HS_HEAVY_B = fallbackHomeserver("hs-heavy-b", 2_000_000_000, true);
    static final Homeserver HS_LIMIT_A = fallbackHomeserver("hs-limit-a", 1 << 23, true);
    static final Homeserver HS_LIMIT_B = fallbackHomeserver("hs-limit-b", 1 << 23, true);
    static final Homeserver HS_SUSPENDED_HEAVY = fallbackHomeserver("hs-suspended-heavy", Integer.MAX_VALUE, true);
    static final Homeserver HS_CLOSED_HEAVY = fallbackHomeserver("hs-closed-heavy", Integer.MAX_VALUE, false);
    static final Homeserver HS_OVER = fallbackHomeserver("hs-over", (1 << 24) - 4, true);
    static final Homeserver HS_ZERO_A = fallbackHomeserver("hs-zero-a", 0, true);
    static final Homeserver HS_ZERO_B = fallbackHomeserver("hs-zero-b", 0, true);
    static final Homeserver HS_ZERO_C = fallbackHomeserver("hs-zero-c", 0, true);
    static final Homeserver HS_FIVE = fallbackHomeserver("hs-five", 5, true);
    static final Homeserver HS_TWO = fallbackHomeserver("hs-two", 2, true);
    static final Homeserver HS_NEGATIVE = fallbackHomeserver("hs-negative", -3, true);

    record RosterFixture(String ref, SignedRoster roster, List<NamedKey> trustedKeys, int threshold) {}

    record PolicyFixture(String ref, RoutingPolicyBundle bundle) {}

    private ClientVerificationVectorsGenerator() {}

    static Homeserver fallbackHomeserver(String id, int weight, boolean acceptsNew) {
        String host = id.substring("hs-".length()) + ".gua.test";
        return new Homeserver(id, host, "https://matrix." + host, "https://account." + host, null, weight,
                acceptsNew, "", Homeserver.SearchVisibility.GLOBAL, List.of());
    }

    public static void main(String[] args) throws Exception {
        Files.createDirectories(OUT.getParent());
        Files.writeString(OUT, render());
        System.out.println("wrote " + OUT);
    }

    /** Byte-identical on every platform: the default printer ends lines with the system separator. */
    static String render() throws Exception {
        DefaultPrettyPrinter printer = new DefaultPrettyPrinter().withObjectIndenter(new DefaultIndenter("  ", "\n"));
        return JSON.writer(printer).writeValueAsString(build()) + "\n";
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
        RosterFixture r8 = fallbackRoster("r8", Instant.parse("2026-10-06T00:00:00Z"), leafHashes,
                new RosterEntry(HS_LIMIT_A, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE),
                new RosterEntry(HS_LIMIT_B, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE),
                new RosterEntry(HS_SUSPENDED_HEAVY, List.of(), ADMIT_CA, RosterEntry.Status.SUSPENDED),
                new RosterEntry(HS_CLOSED_HEAVY, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE));
        RosterFixture r9 = fallbackRoster("r9", Instant.parse("2026-10-07T00:00:00Z"), leafHashes,
                new RosterEntry(HS_BR, brClaims(), ADMIT_BR, RosterEntry.Status.ACTIVE),
                new RosterEntry(HS_OVER, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE));
        RosterFixture r10 = fallbackRoster("r10", Instant.parse("2026-10-08T00:00:00Z"), leafHashes,
                new RosterEntry(HS_ZERO_A, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE),
                new RosterEntry(HS_ZERO_B, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE),
                new RosterEntry(HS_ZERO_C, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE));
        RosterFixture r11 = fallbackRoster("r11", Instant.parse("2026-10-09T00:00:00Z"), leafHashes,
                new RosterEntry(HS_FIVE, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE),
                new RosterEntry(HS_TWO, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE),
                new RosterEntry(HS_NEGATIVE, List.of(), ADMIT_CA, RosterEntry.Status.ACTIVE));
        PolicyFixture brPolicy = new PolicyFixture("br-policy v3", policy);
        PolicyFixture spUnsigned = new PolicyFixture("br-policy v3 without the sp-zone delegate signature",
                policy(GOVERNANCE_A, false, true));

        ObjectNode root = JSON.createObjectNode();
        root.put("vectors", "gua-client-verification.v1");
        root.put("protocol", "docs/verification/gua-resolver-verification-protocol.md");
        root.set("keys", keys());
        root.set("instants", instants());
        root.set("rosters", rosters(r1, r2, r4, prod, prodJson, r5, r6, r7, List.of(r8, r9, r10, r11)));
        root.set("rosterRejections", rosterRejections(r1.roster(), r2.roster(), brMember));
        root.set("log", log(events, leafHashes));
        root.set("policies", policies(brPolicy, spUnsigned));
        root.set("policyRejections", policyRejections(policy));
        root.set("policyValidity", policyValidity(brPolicy));
        root.set("windows", windows());
        root.set("policyLog", policyLog(events, policy, withRules(policy, retargetedRules(policy))));
        root.set("placements", placements(r1, r2, r6, r8, r9, r10, r11, brPolicy, spUnsigned));
        root.set("resolveAnswers", resolveAnswers(r2.roster(), prod, r5.roster(), r7.roster()));
        root.set("ed25519Cases", ed25519Cases());
        return root;
    }

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

    static RosterFixture fallbackRoster(String ref, Instant issuedAt, List<String> leafHashes, RosterEntry... entries) {
        return new RosterFixture(ref, signRoster(7, issuedAt, checkpoint(leafHashes, 7), List.of(entries),
                RosterForm.V1, AUTHORITY_A), List.of(AUTHORITY_A), 1);
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
                             RosterFixture r5, RosterFixture r6, RosterFixture r7, List<RosterFixture> weightRosters) {
        ArrayNode out = JSON.createArrayNode();
        out.add(rosterVector("one homeserver that signs its own entry; one authority signature required", r1));
        out.add(rosterVector("three homeservers with claims, group search and a suspended entry; two signatures "
                + "required", r2));
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

        List<String> weightNames = List.of(
                "weights that add up to the fallback limit, beside heavy entries that take no new accounts",
                "a homeserver with routing claims, and weights one past the fallback limit",
                "three homeservers of weight 0",
                "weights 5, 2 and -3");
        for (int i = 0; i < weightRosters.size(); i++) {
            out.add(rosterVector(weightNames.get(i), weightRosters.get(i)));
        }
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
                "Only authority-b signed, and the client trusts only authority-a."));

        SignedRoster aOnly = signRoster(r2.version(), r2.issuedAt(), r2.logCheckpoint(), r2.entries(),
                RosterForm.V1, AUTHORITY_A);
        out.add(rejection("one signature where two are required", RosterForm.V1, aOnly,
                trusted(List.of(AUTHORITY_A, AUTHORITY_B)), 2, "One valid signature, two required."));

        List<SignedRoster.AuthoritySignature> twice = new ArrayList<>(aOnly.authoritySignatures());
        twice.add(aOnly.authoritySignatures().get(0));
        out.add(rejection("the same signature listed twice", RosterForm.V1, withSignatures(aOnly, twice),
                trusted(List.of(AUTHORITY_A, AUTHORITY_B)), 2,
                "A key counts once, however often it appears."));

        SignedRoster unnamed = withSignatures(r1, List.of(
                new SignedRoster.AuthoritySignature(null, r1.authoritySignatures().get(0).signatureB64())));
        out.add(rejection("a signature without a key id", RosterForm.V1, unnamed, trusted(List.of(AUTHORITY_A)), 1,
                "A signature that names no key counts for none."));

        out.add(rejection("a v1 roster checked against its legacy bytes", RosterForm.LEGACY, r1,
                trusted(List.of(AUTHORITY_A)), 1, "The signature covers the v1 bytes, not the legacy bytes."));

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
                "Hashes remain after the path is complete, which RFC 9162 refuses.");
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
        RoutingPolicyBundle signedByAuthority = policy(AUTHORITY_A, true, true);
        ObjectNode operationalKey = policyVector("signed by the roster authority key, which is not a policy key",
                null, signedByAuthority, List.of(GOVERNANCE_A), 1);
        operationalKey.put("reason", "Only policy keys count, not the roster authority key.");
        operationalKey.put("expectedOutcome", policySignatureOutcome(signedByAuthority, List.of(GOVERNANCE_A)));
        out.add(operationalKey);
        RoutingPolicyBundle retargeted = withRules(policy, retargetedRules(policy));
        ObjectNode retargetedRule = policyVector("a rule target changed after signing", null, retargeted,
                List.of(GOVERNANCE_A), 1);
        retargetedRule.put("reason", "The signed bytes changed, so the signature fails.");
        retargetedRule.put("expectedOutcome", policySignatureOutcome(retargeted, List.of(GOVERNANCE_A)));
        out.add(retargetedRule);
        RoutingPolicyBundle unsigned = withPolicySignatures(policy, null);
        ObjectNode noSignatures = policyVector("a bundle with no signatures list", null, unsigned,
                List.of(GOVERNANCE_A), 1);
        noSignatures.put("reason", "A missing signatures list is the same as an empty one.");
        noSignatures.put("expectedOutcome", policySignatureOutcome(unsigned, List.of(GOVERNANCE_A)));
        out.add(noSignatures);
        ObjectNode noPolicyKeys = policyVector("no policy keys configured", null, policy, List.of(), 1);
        noPolicyKeys.put("reason", "With no trusted policy keys, no bundle can verify.");
        noPolicyKeys.put("expectedOutcome", policySignatureOutcome(policy, List.of()));
        out.add(noPolicyKeys);
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
        window(out, "an expiresAt in the epoch's first millisecond, which is also signed as no expiresAt", notBefore,
                Instant.parse("1970-01-01T00:00:00.000001Z"), inside);
        window(out, "a notBefore at the epoch, which is signed as no notBefore", Instant.EPOCH, expiresAt, inside);
        window(out, "a notBefore later in the same millisecond, compared in whole milliseconds",
                Instant.parse("2030-01-01T00:00:00.000500Z"), null, Instant.parse("2030-01-01T00:00:00.000200Z"));
        window(out, "an expiresAt later in the same millisecond, compared in whole milliseconds", notBefore,
                Instant.parse("2030-01-01T00:00:00.000500Z"), Instant.parse("2030-01-01T00:00:00.000200Z"));
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

    static ArrayNode placements(RosterFixture r1, RosterFixture r2, RosterFixture r6, RosterFixture r8,
                                RosterFixture r9, RosterFixture r10, RosterFixture r11, PolicyFixture policy,
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
            out.add(placement("weighted fallback sample " + i, r2, policy, sample(i)));
        }
        for (int i = 0; i < 4; i++) {
            out.add(placement("weights past the fallback limit make no decision, sample " + i, r6, null, sample(i)));
        }
        for (int i : new int[] {0, 3, 6, 8}) {
            out.add(placement("weights at the fallback limit, sample " + i, r8, null, sample(i)));
        }
        out.add(placement("past the fallback limit a roster claim still decides", r9, null,
                ctx("+5519991112222", "BR", "72411", "Vivo")));
        out.add(placement("past the fallback limit a signed policy rule still decides", r9, policy,
                ctx("+5511987654321", null, null, null)));
        out.add(placement("past the fallback limit, without the sp-zone delegate signature, nothing decides", r9,
                spUnsigned, ctx("+5511987654321", null, null, null)));
        out.add(placement("past the fallback limit the fallback makes no decision", r9, null, sample(0)));
        for (int i = 0; i < 4; i++) {
            out.add(placement("weights all 0, sample " + i, r10, null, sample(i)));
        }
        for (int i = 0; i < 4; i++) {
            out.add(placement("weights 5, 2 and -3, sample " + i, r11, null, sample(i)));
        }
        return out;
    }

    static PlacementContext sample(int i) {
        return ctx("+552199000" + String.format(Locale.ROOT, "%04d", i * 1237), null, null, null);
    }

    static PlacementContext ctx(String phone, String country, String mccmnc, String carrier) {
        return new PlacementContext(phone, country, mccmnc, carrier, null, List.of(), Map.of(), false);
    }

    static ObjectNode placement(String name, RosterFixture rosterFixture, PolicyFixture policyFixture,
                                PlacementContext ctx) {
        SignedRoster roster = rosterFixture.roster();
        RoutingPolicyBundle policy = policyFixture == null ? null : policyFixture.bundle();
        ResolverVerifier verifier = verifierAt(EVALUATED_AT, rosterFixture.trustedKeys(), rosterFixture.threshold());
        Optional<PlacementDecision> d = verifier.reproduceNewAccountDecision(ctx, roster, RosterForm.V1, policy);
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
        v.put("expectedHomeserverId", d.map(x -> x.homeserver().id()).orElse(null));
        v.put("expectedRule", d.map(PlacementDecision::rule).orElse(null));
        v.put("expectedRuleId", d.map(PlacementDecision::ruleId).orElse(null));
        v.put("unsignedRuleAbove", policy != null && verifier.unsignedRuleOutranks(ctx, policy, d));
        if (d.isEmpty() || "weighted-fallback".equals(d.get().ruleId())) {
            List<Homeserver> candidates = roster.activeEntries().stream().map(RosterEntry::homeserver)
                    .filter(Homeserver::acceptsNew).sorted(Comparator.comparing(Homeserver::id)).toList();
            ObjectNode f = v.putObject("fallback");
            f.put("routingKeyUtf8", placed.canonicalRoutingKey());
            f.put("rosterVersion", roster.version());
            ArrayNode cands = f.putArray("candidates");
            for (Homeserver h : candidates) {
                cands.addObject().put("id", h.id()).put("weight", Math.max(0, h.weight()));
            }
            f.put("totalWeight", WeightedFallbackRule.totalWeight(candidates));
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

    static final BigInteger GROUP_ORDER =
            BigInteger.TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));
    static final String SPKI_PREFIX_HEX = "302a300506032b6570032100";
    static final String X25519_SPKI_PREFIX_HEX = "302a300506032b656e032100";
    static final String IDENTITY_POINT_HEX = "01" + "00".repeat(31);
    static final String R_Y_P_PLUS_ONE_HEX = "ee" + "ff".repeat(30) + "7f";

    // Case 9 of ed25519-speccheck (github.com/novifinancial/ed25519-speccheck, Apache-2.0).
    static final String SPECCHECK9_PUBLIC_HEX = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43";
    static final String SPECCHECK9_MESSAGE_HEX = "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41";
    static final String SPECCHECK9_SIGNATURE_HEX = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908";

    private static final String FORGED_MESSAGE_HEX = "6775612d617564697420666f726765642073746174656d656e74";

    /** Small-order R, S = 0 forgeries that pass without the key checks: name, public key, message suffix, R. */
    private static final String[][] WEAK_KEY_FORGERIES = {
            {"identity key (order 1)", "01" + "00".repeat(31), "00", "01" + "00".repeat(31)},
            {"key of order 2", "ec" + "ff".repeat(30) + "7f", "00", "01" + "00".repeat(31)},
            {"all-zero key (order 4)", "00".repeat(32), "00", "01" + "00".repeat(31)},
            {"key of order 4 with x negative", "00".repeat(31) + "80", "00", "01" + "00".repeat(31)},
            {"key of order 8", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "00",
                    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"},
            {"key of order 8 with x negative", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
                    "02", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"},
            {"key of order 8, second y", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "00",
                    "00".repeat(32)},
            {"key of order 8, second y, x positive",
                    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "00",
                    "ec" + "ff".repeat(30) + "7f"},
            {"non-canonical key with y = p", "ed" + "ff".repeat(30) + "7f", "00", "01" + "00".repeat(31)},
            {"non-canonical key with y = p and the sign bit set", "ed" + "ff".repeat(31), "01",
                    "ec" + "ff".repeat(30) + "7f"},
            {"non-canonical key with y = p + 1", "ee" + "ff".repeat(30) + "7f", "00", "01" + "00".repeat(31)},
            {"non-canonical key with x = 0 and the sign bit set", "01" + "00".repeat(30) + "80", "",
                    "01" + "00".repeat(31)},
    };

    /**
     * Every verifier requires one base64 spelling, canonical points outside the small-order subgroup, and S below
     * the group order. Mixed-order keys and cofactored versus cofactorless verification are not yet specified.
     */
    static ArrayNode ed25519Cases() {
        Ed25519.KeyPairB64 key = AUTHORITY_A.pair();
        String spki = key.publicKeyB64();
        byte[] message = new byte[0];
        byte[] signature = B64.decode(Ed25519.sign(Ed25519.privateKey(key.privateKeyB64()), message));
        String signatureB64 = B64E.encodeToString(signature);
        if (!signatureB64.contains("+")) {
            throw new IllegalStateException("the URL-safe case needs a '+' in the signature");
        }
        BigInteger s = littleEndian(Arrays.copyOfRange(signature, 32, 64));

        ArrayNode out = JSON.createArrayNode();
        ed25519Case(out, "valid signature", spki, message, signatureB64, true);
        ed25519Case(out, "S plus the group order", spki, message, withS(signature, s.add(GROUP_ORDER)), false);
        ed25519Case(out, "S with the top bit set", spki, message, withS(signature, s.setBit(255)), false);
        ed25519Case(out, "R encoded with y = p + 1, under the identity key with S = 0", spkiB64(IDENTITY_POINT_HEX),
                message, B64E.encodeToString(HEX.parseHex(R_Y_P_PLUS_ONE_HEX + "00".repeat(32))), false);
        ed25519Case(out, "R with x = 0 and the sign bit set", spkiB64(SPECCHECK9_PUBLIC_HEX),
                HEX.parseHex(SPECCHECK9_MESSAGE_HEX), B64E.encodeToString(HEX.parseHex(SPECCHECK9_SIGNATURE_HEX)),
                false);
        ed25519Case(out, "signature of 63 bytes", spki, message,
                B64E.encodeToString(Arrays.copyOf(signature, 63)), false);
        ed25519Case(out, "signature of 65 bytes", spki, message,
                B64E.encodeToString(Arrays.copyOf(signature, 65)), false);
        ed25519Case(out, "signature in the URL-safe alphabet", spki, message,
                signatureB64.replace('+', '-').replace('/', '_'), false);
        ed25519Case(out, "signature with a line break", spki, message,
                signatureB64.substring(0, 44) + "\n" + signatureB64.substring(44), false);
        ed25519Case(out, "signature with one padding character", spki, message,
                signatureB64.substring(0, signatureB64.length() - 1), false);
        ed25519Case(out, "public key with a trailing byte", B64E.encodeToString(
                Arrays.copyOf(B64.decode(spki), B64.decode(spki).length + 1)), message, signatureB64, false);
        ed25519Case(out, "public key with the X25519 algorithm identifier",
                B64E.encodeToString(HEX.parseHex(X25519_SPKI_PREFIX_HEX + Rfc8032Keys.TEST1_PUBLIC_HEX)), message,
                signatureB64, false);
        ed25519Case(out, "signature without padding", spki, message, signatureB64.replace("=", ""), false);
        ed25519Case(out, "signature with an extra padding character", spki, message, signatureB64 + "=", false);
        ed25519Case(out, "signature with non-zero trailing bits", spki, message,
                withNonZeroTrailingBits(signatureB64), false);
        ed25519Case(out, "public key without padding", spki.replace("=", ""), message, signatureB64, false);
        ed25519Case(out, "public key with non-zero trailing bits", withNonZeroTrailingBits(spki), message,
                signatureB64, false);
        ed25519Case(out, "public key that is not a curve point", spkiB64("02" + "00".repeat(31)), message,
                signatureB64, false);
        ed25519Case(out, "public key with NULL algorithm parameters", B64E.encodeToString(HEX.parseHex(
                "302c300706032b65700500032100" + HEX.formatHex(Arrays.copyOfRange(B64.decode(spki), 12, 44)))),
                message, signatureB64, false);
        for (String[] forgery : WEAK_KEY_FORGERIES) {
            ed25519Case(out, "forgery under the " + forgery[0], spkiB64(forgery[1]),
                    HEX.parseHex(FORGED_MESSAGE_HEX + forgery[2]),
                    B64E.encodeToString(HEX.parseHex(forgery[3] + "00".repeat(32))), false);
        }
        return out;
    }

    static void ed25519Case(ArrayNode out, String name, String publicKeySpkiB64, byte[] message,
                            String signatureB64, boolean verifies) {
        ObjectNode n = out.addObject();
        n.put("name", name);
        n.put("publicKeySpkiB64", publicKeySpkiB64);
        n.put("messageHex", HEX.formatHex(message));
        n.put("signatureB64", signatureB64);
        n.put("verifies", verifies);
    }

    static String withNonZeroTrailingBits(String padded) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int last = padded.replace("=", "").length() - 1;
        char bumped = alphabet.charAt(alphabet.indexOf(padded.charAt(last)) + 1);
        return padded.substring(0, last) + bumped + padded.substring(last + 1);
    }

    static String spkiB64(String publicKeyHex) {
        return B64E.encodeToString(HEX.parseHex(SPKI_PREFIX_HEX + publicKeyHex));
    }

    static BigInteger littleEndian(byte[] bytes) {
        byte[] bigEndian = bytes.clone();
        for (int i = 0; i < bigEndian.length / 2; i++) {
            byte t = bigEndian[i];
            bigEndian[i] = bigEndian[bigEndian.length - 1 - i];
            bigEndian[bigEndian.length - 1 - i] = t;
        }
        return new BigInteger(1, bigEndian);
    }

    static String withS(byte[] signature, BigInteger s) {
        byte[] bigEndian = s.toByteArray();
        byte[] out = Arrays.copyOf(signature, 64);
        for (int i = 0; i < 32; i++) {
            int j = bigEndian.length - 1 - i;
            out[32 + i] = j >= 0 ? bigEndian[j] : 0;
        }
        return B64E.encodeToString(out);
    }
}
