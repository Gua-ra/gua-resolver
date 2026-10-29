package global.gua.resolver.verify;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.placement.PlacementEngine;
import global.gua.resolver.placement.PlacementRule;
import global.gua.resolver.placement.rules.ClaimRule;
import global.gua.resolver.placement.rules.PolicyRoutingRule;
import global.gua.resolver.placement.rules.WeightedFallbackRule;
import global.gua.resolver.policy.CanonicalRoutingPolicy;
import global.gua.resolver.policy.CompositeRoutingPolicyProvider;
import global.gua.resolver.policy.DelegationZone;
import global.gua.resolver.policy.PolicyTransparencyListener;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicyRule;
import global.gua.resolver.policy.RoutingPolicySource;
import global.gua.resolver.policy.RoutingPolicyVerifier;
import global.gua.resolver.policy.RoutingPolicyVerifier.RoutingPolicyVerificationException;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterForm;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.RosterVerifier;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;

/**
 * Reference for the checks a client runs on what a resolver serves: the roster's authority signatures, the
 * policy bundle's signatures and validity window, where a {@code /resolve} answer sits in the roster, and the
 * placement of a new account. It reuses the server's encoders and placement rules. The member block and
 * transparency-log checks are specified in the protocol and run only in the apps.
 *
 * <p>A reproduced placement holds for one roster version, because the weighted fallback seeds on it.
 */
public final class ResolverVerifier {

    private final RosterVerifier rosterVerifier;
    private final RoutingPolicyVerifier policyVerifier;
    private final Set<String> authorityKeyIds;
    private final Set<String> policyKeyIds;
    private final int policyThreshold;
    private final Clock clock;

    public ResolverVerifier(List<ResolverProperties.TrustedKey> authorityKeys, int authorityThreshold,
                            List<ResolverProperties.TrustedKey> policyKeys, int policyThreshold) {
        this(authorityKeys, authorityThreshold, policyKeys, policyThreshold, Clock.systemUTC());
    }

    /**
     * @param policyKeys the only keys a policy bundle may be signed under. An empty list verifies no bundle; there
     *                   is no fallback to the authority keys, which the server still has.
     */
    public ResolverVerifier(List<ResolverProperties.TrustedKey> authorityKeys, int authorityThreshold,
                            List<ResolverProperties.TrustedKey> policyKeys, int policyThreshold, Clock clock) {
        ResolverProperties rosterProps = new ResolverProperties();
        rosterProps.getAuthority().setThreshold(authorityThreshold);
        rosterProps.getAuthority().setTrustedKeys(authorityKeys == null ? List.of() : authorityKeys);
        this.rosterVerifier = new RosterVerifier(rosterProps);
        this.policyVerifier = RoutingPolicyVerifier.forKeys(policyKeys == null ? List.of() : policyKeys,
                policyThreshold);
        this.authorityKeyIds = keyIds(authorityKeys);
        this.policyKeyIds = keyIds(policyKeys);
        this.policyThreshold = Math.max(1, policyThreshold);
        this.clock = clock;
    }

    private static Set<String> keyIds(List<ResolverProperties.TrustedKey> keys) {
        return keys == null ? Set.of()
                : keys.stream().map(ResolverProperties.TrustedKey::getId).filter(Objects::nonNull)
                        .collect(Collectors.toUnmodifiableSet());
    }

    /** Throws unless enough trusted authority keys signed the bytes of this roster form. */
    public void verifyRoster(SignedRoster roster, RosterForm form) {
        rosterVerifier.requireVerified(roster, form);
    }

    /** The rosterSignature outcome a client reports for this roster, in the report's {@code outcome(reason)} form. */
    public String rosterSignatureOutcome(SignedRoster roster, RosterForm form) {
        return signatureOutcome(roster.authoritySignatures().stream()
                        .map(SignedRoster.AuthoritySignature::authorityKeyId).toList(),
                authorityKeyIds, rosterVerifier.countValidSignatures(roster, form), rosterVerifier.threshold());
    }

    /** The signature step of the policy check, in the report's {@code outcome(reason)} form. */
    public String policySignatureOutcome(RoutingPolicyBundle policy) {
        if (policyKeyIds.isEmpty()) {
            return "unverifiable(no_policy_keys)";
        }
        return signatureOutcome(policy.signatures().stream()
                        .map(RoutingPolicyBundle.PolicySignature::authorityKeyId).toList(),
                policyKeyIds, policyVerifier.countValidSignatures(policy), policyThreshold);
    }

    private static String signatureOutcome(List<String> signedBy, Set<String> trustedIds, int valid, int threshold) {
        if (valid >= threshold) {
            return "valid";
        }
        if (signedBy.stream().noneMatch(trustedIds::contains)) {
            return "invalid(unknown_key_id)";
        }
        return valid == 0 ? "invalid(bad_signature)" : "invalid(threshold_not_met)";
    }

    /**
     * The policy check's log step for a served bundle whose signatures and window passed, or for a {@code 404} when
     * {@code served} is null. The leaves the checkpoint signs must hash to its root, and the bundle must be the newest
     * version of its policy among them. A 404 passes only while none of them publishes a policy.
     */
    public static String policyLogOutcome(List<TransparencyLog.Event> events, SignedRoster.LogCheckpoint checkpoint,
                                          RoutingPolicyBundle served) {
        int size = Math.toIntExact(checkpoint.size());
        if (events.size() < size || !MerkleTree.root(events.subList(0, size).stream()
                .map(TransparencyLog.Event::leafHash).toList()).equals(checkpoint.merkleRoot())) {
            return "invalid(log_mismatch)";
        }
        List<TransparencyLog.Event> published = events.subList(0, size).stream()
                .filter(ResolverVerifier::publishesPolicy).toList();
        if (served == null) {
            return published.isEmpty() ? "notPresent" : "unverifiable(policy_not_served)";
        }
        String bundleHash = MerkleTree.sha256Hex(CanonicalRoutingPolicy.bytes(served));
        if (published.stream().noneMatch(e -> bundleHash.equals(e.payloadHash()))) {
            boolean later = events.subList(size, events.size()).stream()
                    .anyMatch(e -> publishesPolicy(e) && bundleHash.equals(e.payloadHash()));
            return later ? "unverifiable(policy_newer_than_checkpoint)" : "invalid(policy_not_logged)";
        }
        boolean superseded = published.stream().anyMatch(e -> publishesNewerVersion(e.homeserverId(), served));
        return superseded ? "unverifiable(policy_superseded)" : "valid";
    }

    private static boolean publishesPolicy(TransparencyLog.Event event) {
        return PolicyTransparencyListener.EVENT_TYPE.equals(event.type());
    }

    /** A POLICY_PUBLISH subject is {@code <policyId>:v<version>}. */
    private static boolean publishesNewerVersion(String subject, RoutingPolicyBundle served) {
        int at = subject == null ? -1 : subject.lastIndexOf(":v");
        if (at < 0 || !subject.substring(0, at).equals(served.policyId())) {
            return false;
        }
        try {
            return Long.parseLong(subject.substring(at + 2)) > served.version();
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /** Throws unless enough policy keys signed the bundle and it is in effect now. */
    public void verifyPolicy(RoutingPolicyBundle policy) {
        policyVerifier.requireVerified(policy);
        if (!policy.inEffectAt(clock.instant())) {
            throw new RoutingPolicyVerificationException(
                    "routing policy " + policy.policyId() + " v" + policy.version() + " is not in effect");
        }
    }

    /** The server's placement for a new account with this context, after verifying the roster and the policy. */
    public PlacementDecision reproduceNewAccountDecision(PlacementContext context, SignedRoster roster,
                                                         RosterForm form, RoutingPolicyBundle policy) {
        verifyRoster(roster, form);
        RosterStore store = fixedRoster(roster);
        List<PlacementRule> rules = new ArrayList<>();
        if (policy != null) {
            verifyPolicy(policy);
            rules.add(new PolicyRoutingRule(new CompositeRoutingPolicyProvider(List.of(fixedPolicy(policy))),
                    store, policyVerifier, clock));
        }
        rules.add(new ClaimRule(store));
        rules.add(new WeightedFallbackRule(store));
        return new PlacementEngine(rules).decideWithTrace(context.withoutUnverifiedClaims());
    }

    /**
     * Whether a rule that matches this context but sits in a zone without a valid delegate signature ranks above
     * the rule that decided. Neither the bundle signatures nor its log leaf cover delegate signatures, so a
     * client cannot tell a missing one from a removed one.
     */
    public boolean unsignedRuleOutranks(PlacementContext context, RoutingPolicyBundle policy,
                                        PlacementDecision decision) {
        Set<String> signedZones = policyVerifier.delegateVerifiedZones(policy);
        Map<String, DelegationZone> zones = policy.delegationZones().stream()
                .collect(Collectors.toMap(DelegationZone::id, Function.identity(), (a, b) -> a));
        Comparator<RoutingPolicyRule> rank = Comparator.comparingInt(RoutingPolicyRule::priority)
                .thenComparing(RoutingPolicyRule::id);
        Optional<RoutingPolicyRule> decided = policy.rules().stream()
                .filter(r -> decision.policyId() != null && r.id().equals(decision.ruleId()))
                .findFirst();
        Instant now = clock.instant();
        PlacementContext placed = context.withoutUnverifiedClaims();
        return policy.rules().stream()
                .filter(RoutingPolicyRule::isEnabled)
                .filter(r -> !signedZones.contains(r.delegatedZoneId()))
                .filter(r -> zones.containsKey(r.delegatedZoneId()) && zones.get(r.delegatedZoneId()).inEffectAt(now))
                .filter(r -> PolicyRoutingRule.matches(r, placed))
                .anyMatch(r -> decided.isEmpty() || rank.compare(r, decided.get()) < 0);
    }

    /** How a {@code /resolve} answer relates to a roster. */
    public enum HomeserverMatch {
        /** An ACTIVE entry has the answer's server name, base URL and auth issuer. */
        ACTIVE_MATCH,
        /** Only entries that are not ACTIVE have all three. */
        INACTIVE,
        /** An entry has the server name, but none has all three. */
        FIELD_MISMATCH,
        /** No entry has the server name. */
        NOT_IN_ROSTER
    }

    /** A classification and the entry that decided it, which is null for NOT_IN_ROSTER. */
    public record Located(HomeserverMatch match, RosterEntry entry) {}

    /**
     * Where a {@code /resolve} answer sits in a roster the caller has verified. The strongest classification
     * wins whatever the entry order, and a tie goes to the entry served first. Region is not compared.
     */
    public static Located locate(String serverName, String baseUrl, String masIssuer, SignedRoster roster) {
        List<RosterEntry> named = roster.entries().stream()
                .filter(e -> serverName.equals(e.homeserver().serverName()))
                .toList();
        List<RosterEntry> sameEndpoint = named.stream()
                .filter(e -> baseUrl.equals(e.homeserver().baseUrl())
                        && Objects.equals(masIssuer, e.homeserver().masIssuer()))
                .toList();
        return sameEndpoint.stream().filter(RosterEntry::isActive).findFirst()
                .map(e -> new Located(HomeserverMatch.ACTIVE_MATCH, e))
                .or(() -> sameEndpoint.stream().findFirst().map(e -> new Located(HomeserverMatch.INACTIVE, e)))
                .or(() -> named.stream().findFirst().map(e -> new Located(HomeserverMatch.FIELD_MISMATCH, e)))
                .orElse(new Located(HomeserverMatch.NOT_IN_ROSTER, null));
    }

    private static RosterStore fixedRoster(SignedRoster roster) {
        return new RosterStore() {
            @Override public SignedRoster current() { return roster; }
            @Override public SignedRoster refresh() { return roster; }
        };
    }

    private static RoutingPolicySource fixedPolicy(RoutingPolicyBundle policy) {
        return new RoutingPolicySource() {
            @Override public Optional<RoutingPolicyBundle> current() { return Optional.of(policy); }
            @Override public PolicySourceStatus status() {
                return new PolicySourceStatus("verifier", true, policy.version(), null, "verifier");
            }
        };
    }
}
