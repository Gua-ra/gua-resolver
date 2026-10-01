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

/** Reference client verifier: reproduces new-account placement from the verified roster and policy. */
public final class ResolverVerifier {

    private final RosterVerifier rosterVerifier;
    private final RoutingPolicyVerifier policyVerifier;

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

    public void verifyRoster(SignedRoster roster) {
        rosterVerifier.requireVerified(roster);
    }

    public void verifyPolicy(RoutingPolicyBundle policy) {
        policyVerifier.requireVerified(policy);
    }

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
