package global.gua.resolver.placement;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.rules.PolicyRoutingRule;
import global.gua.resolver.placement.rules.ClaimRule;
import global.gua.resolver.placement.rules.WeightedFallbackRule;
import global.gua.resolver.policy.CompositeRoutingPolicyProvider;
import global.gua.resolver.policy.DelegationZone;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicyRule;
import global.gua.resolver.policy.RoutingPolicySource;
import global.gua.resolver.policy.RoutingPolicyVerifier;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the placement pipeline: a carrier claiming its MCCMNC wins, a verified affiliation claim
 * wins, an unverified one does not, and otherwise the weighted fallback always yields an enabled homeserver.
 * Pure (no Spring). Signed-policy tests use a permissive verifier so they exercise placement logic; the
 * delegation cryptography itself is covered in RoutingPolicyTest.
 */
class PlacementEngineTest {

    private static final Homeserver CARRIER = new Homeserver(
            "carrier", "vivo.gua.global", "https://carrier", "https://carrier/auth", "BR", 1, true, null);
    private static final Homeserver UNI = new Homeserver(
            "uni", "usp.gua.global", "https://uni", "https://uni/auth", "BR", 1, true, null);
    private static final Homeserver DEFAULT = new Homeserver(
            "default", "gua.global", "https://default", "https://default/auth", null, 5, true, null);

    private static RosterStore rosterOf(RosterEntry... entries) {
        SignedRoster roster = new SignedRoster(1L, Instant.now(), List.of(entries),
                new SignedRoster.LogCheckpoint("test", entries.length), List.of());
        return new RosterStore() {
            @Override public SignedRoster current() { return roster; }
            @Override public SignedRoster refresh() { return roster; }
        };
    }

    private static RosterEntry entry(Homeserver hs, ClaimPredicate... claims) {
        return new RosterEntry(hs, List.of(claims), Instant.now(), RosterEntry.Status.ACTIVE);
    }

    private static PlacementEngine engineFor(RosterStore store) {
        // Registered out of priority order on purpose — the engine must sort them.
        return new PlacementEngine(List.of(new WeightedFallbackRule(store), new ClaimRule(store)));
    }

    /** Verifier that treats every zone as delegate-verified (requireSignatures=false), for placement-logic tests. */
    private static RoutingPolicyVerifier permissiveVerifier() {
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setRequireSignatures(false);
        return new RoutingPolicyVerifier(props);
    }

    private static DelegationZone zone(String id, DelegationZone.ScopeType type, String scope,
                                       String authority, List<String> homeservers,
                                       Instant notBefore, Instant expiresAt) {
        return new DelegationZone(id, type, scope, authority, "delegate-" + id, "DPUB",
                homeservers, notBefore, expiresAt);
    }

    @Test
    void carrierClaimByMccmncWins() {
        var carrierClaim = new ClaimPredicate(null, "72411", null, null, null, null, null, 100);
        var engine = engineFor(rosterOf(entry(CARRIER, carrierClaim), entry(DEFAULT)));

        var ctx = new PlacementContext("+5511987654321", "BR", "72411", "Vivo", null, List.of(), Map.of(), false);

        assertThat(engine.decide(ctx).id()).isEqualTo("carrier");
    }

    @Test
    void verifiedAffiliationClaimWins() {
        var uniClaim = new ClaimPredicate(null, null, null, null, "usp.br", null, null, 100);
        var engine = engineFor(rosterOf(entry(UNI, uniClaim), entry(DEFAULT)));

        // claimsVerified=true means the affiliation came from a signature-verified envelope.
        var ctx = new PlacementContext("+5511000000000", "BR", null, null, null, List.of("usp.br"), Map.of(), true);

        assertThat(engine.decide(ctx).id()).isEqualTo("uni");
    }

    @Test
    void unverifiedAffiliationIsIgnoredByClaimRule() {
        var uniClaim = new ClaimPredicate(null, null, null, null, "usp.br", null, null, 100);
        var engine = engineFor(rosterOf(entry(UNI, uniClaim), entry(DEFAULT)));

        // A self-asserted (unverified) affiliation must NOT grant institutional placement; it falls back.
        var ctx = new PlacementContext("+5511000000000", "BR", null, null, null, List.of("usp.br"), Map.of(), false);

        assertThat(engine.decideWithTrace(ctx).rule()).isEqualTo("WeightedFallbackRule");
    }

    @Test
    void noClaimMatchFallsBackToAnEnabledHomeserver() {
        var carrierClaim = new ClaimPredicate(null, "72411", null, null, null, null, null, 100);
        var engine = engineFor(rosterOf(entry(CARRIER, carrierClaim), entry(DEFAULT)));

        // A phone whose carrier nobody claims must still be placed (on an acceptsNew homeserver).
        var ctx = new PlacementContext("+15555550100", "US", "31000", "Verizon", null, List.of(), Map.of(), false);

        var chosen = engine.decide(ctx);
        assertThat(chosen).isNotNull();
        assertThat(chosen.acceptsNew()).isTrue();
        assertThat(List.of("carrier", "default")).contains(chosen.id());
    }

    @Test
    void weightedFallbackIsDeterministicForTheSameContextAndRoster() {
        var engine = engineFor(rosterOf(entry(CARRIER), entry(UNI), entry(DEFAULT)));
        var ctx = new PlacementContext("+15555550100", "US", "31000", "Verizon", null, List.of(), Map.of(), false);

        String first = engine.decide(ctx).id();

        for (int i = 0; i < 20; i++) {
            assertThat(engine.decide(ctx).id()).isEqualTo(first);
        }
    }

    @Test
    void signedPolicyPhoneDelegationWinsBeforeFallback() {
        RoutingPolicyBundle policy = new RoutingPolicyBundle(
                RoutingPolicyBundle.SCHEMA_VERSION,
                "br-carrier-policy",
                7,
                Instant.now(),
                Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600),
                List.of(zone("vivo-sp", DelegationZone.ScopeType.PHONE_PREFIX,
                        "+55119", "carrier:vivo", List.of("carrier"), null, null)),
                List.of(new RoutingPolicyRule("vivo-sp-portable", 10,
                        RoutingPolicyRule.MatchType.PHONE_PREFIX, "+551198", null, null,
                        "carrier", "vivo-sp", "portable carrier routing within delegated prefix",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true),
                List.of(), List.of());
        RosterStore store = rosterOf(entry(CARRIER), entry(DEFAULT));
        var engine = new PlacementEngine(List.of(new WeightedFallbackRule(store),
                new PolicyRoutingRule(provider(policy), store, permissiveVerifier())));

        var decision = engine.decideWithTrace(PlacementContext.forPhone("+5511987654321"));

        assertThat(decision.homeserver().id()).isEqualTo("carrier");
        assertThat(decision.policyId()).isEqualTo("br-carrier-policy");
        assertThat(decision.delegatedZoneId()).isEqualTo("vivo-sp");
        assertThat(decision.assignmentPolicy()).isEqualTo("PORTABLE");
    }

    @Test
    void signedPolicyInstitutionDomainDelegationMatchesVerifiedAffiliation() {
        RoutingPolicyBundle policy = institutionPolicy(null, null);
        RosterStore store = rosterOf(entry(UNI), entry(DEFAULT));
        var engine = new PlacementEngine(List.of(new WeightedFallbackRule(store),
                new PolicyRoutingRule(provider(policy), store, permissiveVerifier())));

        var ctx = new PlacementContext("+5511000000000", "BR", null, null, null,
                List.of("students.usp.br"), Map.of(), true);

        var decision = engine.decideWithTrace(ctx);

        assertThat(decision.homeserver().id()).isEqualTo("uni");
        assertThat(decision.assignmentPolicy()).isEqualTo("REQUIRES_CONFIRMATION");
    }

    @Test
    void institutionPolicyIgnoresUnverifiedAffiliationClaims() {
        RoutingPolicyBundle policy = institutionPolicy(null, null);
        RosterStore store = rosterOf(entry(UNI), entry(DEFAULT));
        var engine = new PlacementEngine(List.of(new WeightedFallbackRule(store),
                new PolicyRoutingRule(provider(policy), store, permissiveVerifier())));

        var ctx = new PlacementContext("+5511000000000", "BR", null, null, null,
                List.of("students.usp.br"), Map.of(), false);

        assertThat(engine.decideWithTrace(ctx).rule()).isEqualTo("WeightedFallbackRule");
    }

    @Test
    void expiredDelegationZoneIsNotAppliedEvenForVerifiedClaims() {
        RoutingPolicyBundle policy = institutionPolicy(
                Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600));   // expired zone window
        RosterStore store = rosterOf(entry(UNI), entry(DEFAULT));
        var engine = new PlacementEngine(List.of(new WeightedFallbackRule(store),
                new PolicyRoutingRule(provider(policy), store, permissiveVerifier())));

        var ctx = new PlacementContext("+5511000000000", "BR", null, null, null,
                List.of("students.usp.br"), Map.of(), true);

        // Even with verified claims, a rule inside an expired delegation zone must not route.
        assertThat(engine.decideWithTrace(ctx).rule()).isEqualTo("WeightedFallbackRule");
    }

    @Test
    void claimedButNotAcceptingNewIsNotPlacedThere() {
        var closed = new Homeserver("closed", "closed.gua.global", "https://c", "https://c/auth", "BR", 1, false, null);
        var carrierClaim = new ClaimPredicate(null, "72411", null, null, null, null, null, 100);
        var engine = engineFor(rosterOf(entry(closed, carrierClaim), entry(DEFAULT)));

        var ctx = new PlacementContext("+5511987654321", "BR", "72411", "Vivo", null, List.of(), Map.of(), false);

        // The claiming homeserver isn't accepting new accounts, so placement falls through to the default.
        assertThat(engine.decide(ctx).id()).isEqualTo("default");
    }

    private static RoutingPolicyBundle institutionPolicy(Instant zoneNotBefore, Instant zoneExpiresAt) {
        return new RoutingPolicyBundle(
                RoutingPolicyBundle.SCHEMA_VERSION,
                "institution-policy",
                3,
                Instant.now(),
                Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600),
                List.of(zone("usp-domain", DelegationZone.ScopeType.INSTITUTION_DOMAIN,
                        "usp.br", "institution:usp", List.of("uni"), zoneNotBefore, zoneExpiresAt)),
                List.of(new RoutingPolicyRule("usp-affiliates", 10,
                        RoutingPolicyRule.MatchType.INSTITUTION_DOMAIN, "usp.br", null, null,
                        "uni", "usp-domain", "verified institution domain",
                        RoutingPolicyRule.AssignmentPolicy.REQUIRES_CONFIRMATION, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true),
                List.of(), List.of());
    }

    private static CompositeRoutingPolicyProvider provider(RoutingPolicyBundle policy) {
        return new CompositeRoutingPolicyProvider(List.of(new RoutingPolicySource() {
            @Override public Optional<RoutingPolicyBundle> current() { return Optional.of(policy); }
            @Override public PolicySourceStatus status() {
                return new PolicySourceStatus("test", true, policy.version(), Instant.now(), "ok");
            }
        }));
    }
}
