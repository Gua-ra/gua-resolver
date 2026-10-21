package global.gua.resolver.verify;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementEngine;
import global.gua.resolver.placement.PlacementRule;
import global.gua.resolver.placement.rules.ClaimRule;
import global.gua.resolver.placement.rules.PolicyRoutingRule;
import global.gua.resolver.placement.rules.WeightedFallbackRule;
import global.gua.resolver.policy.CompositeRoutingPolicyProvider;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicySource;
import global.gua.resolver.policy.RoutingPolicyVerifier;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.RosterVerifier;
import global.gua.resolver.roster.SignedRoster;

/**
 * Reference client-side verifier. Resolver placement is a re-evaluation of the same rules over the same
 * inputs (verified roster, verified policy, context), so a client does not have to trust a resolver's
 * {@code /resolve} answer: it fetches the signed roster and signed policy, verifies their authority (k-of-n)
 * and delegate signatures, and reproduces the decision locally. The answer is stable only for a fixed
 * transparency-log size, because the weighted fallback reseeds on every log leaf. This class reuses the
 * server's own verification and placement code so the two can never diverge (see
 * docs/verification/gua-resolver-verification-protocol.md); platform verifiers port the same spec.
 *
 * <p>Existing-account (directory) results are not verifiable per mapping: no per-lookup inclusion proof is
 * served. What a client can check is that the returned homeserver id is currently ACTIVE in the verified
 * roster.
 */
public final class ResolverVerifier {

    private final RosterVerifier rosterVerifier;
    private final RoutingPolicyVerifier policyVerifier;

    /**
     * @param authorityKeys      published authority public keys (n) the client trusts, for the roster
     * @param authorityThreshold k of n required for a roster authority signature
     * @param policyKeys         the keys a policy bundle must verify under: the federation's governance keys
     *                           once a genesis is pinned. There is no fallback to the authority keys, so an
     *                           empty list verifies nothing rather than accepting bundles signed by the
     *                           operational roster key
     * @param policyThreshold    k required for a policy signature
     */
    public ResolverVerifier(List<ResolverProperties.TrustedKey> authorityKeys, int authorityThreshold,
                            List<ResolverProperties.TrustedKey> policyKeys, int policyThreshold) {
        // The policy verifier gets no authority keys, so an empty policy key list verifies nothing.
        ResolverProperties rosterProps = new ResolverProperties();
        rosterProps.getAuthority().setThreshold(authorityThreshold);
        rosterProps.getAuthority().setTrustedKeys(authorityKeys == null ? List.of() : authorityKeys);

        ResolverProperties policyProps = new ResolverProperties();
        policyProps.getPolicy().setRequireSignatures(true);
        policyProps.getPolicy().setSignatureThreshold(policyThreshold);
        policyProps.getPolicy().setTrustedKeys(policyKeys == null ? List.of() : policyKeys);

        this.rosterVerifier = new RosterVerifier(rosterProps);
        this.policyVerifier = new RoutingPolicyVerifier(policyProps);
    }

    /** Verify the roster carries a valid k-of-n authority signature over its canonical bytes; throws if not. */
    public void verifyRoster(SignedRoster roster) {
        rosterVerifier.requireVerified(roster);
    }

    /** Verify the policy's authority threshold signature; throws if not. */
    public void verifyPolicy(RoutingPolicyBundle policy) {
        policyVerifier.requireVerified(policy);
    }

    /**
     * Independently reproduce the homeserver a new account with this context must be placed on, from verified
     * artifacts. Verifies the roster (always) and the policy (when present) first, then runs the exact
     * deterministic placement pipeline the server runs.
     */
    public Homeserver reproduceNewAccountPlacement(PlacementContext context, SignedRoster roster,
                                                   RoutingPolicyBundle policy) {
        rosterVerifier.requireVerified(roster);
        RosterStore store = fixedRoster(roster);
        List<PlacementRule> rules = new ArrayList<>();
        if (policy != null) {
            policyVerifier.requireVerified(policy);
            rules.add(new PolicyRoutingRule(
                    new CompositeRoutingPolicyProvider(List.of(fixedPolicy(policy))), store, policyVerifier));
        }
        rules.add(new ClaimRule(store));
        rules.add(new WeightedFallbackRule(store));
        return new PlacementEngine(rules).decide(context);
    }

    /**
     * True iff a resolver's register answer matches the independently reproduced placement. A mismatch means
     * the resolver returned a homeserver the verified artifacts do not justify (misrouting).
     */
    public boolean verifyRegisterDecision(String returnedHomeserverId, PlacementContext context,
                                          SignedRoster roster, RoutingPolicyBundle policy) {
        return reproduceNewAccountPlacement(context, roster, policy).id().equals(returnedHomeserverId);
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
