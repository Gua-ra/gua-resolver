package global.gua.resolver.placement.rules;

import java.util.Comparator;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.claims.RoutingClaimsVerifier;
import global.gua.resolver.placement.PlacementContext;
import global.gua.resolver.placement.PlacementDecision;
import global.gua.resolver.placement.PlacementRule;
import global.gua.resolver.policy.CompositeRoutingPolicyProvider;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicyRule;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;

/**
 * First-class signed policy routing. This rule is data-driven by a verified policy bundle and only targets
 * homeservers that are already active in the signed roster.
 */
@Component
@Order(50)
public class PolicyRoutingRule implements PlacementRule {

    private final CompositeRoutingPolicyProvider policies;
    private final RosterStore rosterStore;

    public PolicyRoutingRule(CompositeRoutingPolicyProvider policies, RosterStore rosterStore) {
        this.policies = policies;
        this.rosterStore = rosterStore;
    }

    @Override
    public Optional<PlacementDecision> evaluate(PlacementContext context) {
        return policies.current().flatMap(policy -> evaluate(policy, context));
    }

    private Optional<PlacementDecision> evaluate(RoutingPolicyBundle policy, PlacementContext context) {
        Map<String, Homeserver> activeTargets = rosterStore.current().activeEntries().stream()
                .map(RosterEntry::homeserver)
                .filter(Homeserver::acceptsNew)
                .collect(Collectors.toMap(Homeserver::id, Function.identity()));

        return (policy.rules() == null ? java.util.List.<RoutingPolicyRule>of() : policy.rules()).stream()
                .filter(RoutingPolicyRule::isEnabled)
                .sorted(Comparator.comparingInt(RoutingPolicyRule::priority)
                        .thenComparing(RoutingPolicyRule::id))
                .filter(rule -> matches(rule, context))
                .map(rule -> decision(policy, rule, activeTargets.get(rule.targetHomeserverId())))
                .flatMap(Optional::stream)
                .findFirst();
    }

    private Optional<PlacementDecision> decision(RoutingPolicyBundle policy, RoutingPolicyRule rule,
                                                 Homeserver target) {
        if (target == null) {
            return Optional.empty();
        }
        return Optional.of(new PlacementDecision(target, name(), rule.id(),
                rule.reason() == null || rule.reason().isBlank() ? "matched signed routing policy" : rule.reason(),
                policy.policyId(), policy.version(), rule.delegatedZoneId(),
                rule.effectiveAssignmentPolicy().name()));
    }

    private static boolean matches(RoutingPolicyRule rule, PlacementContext context) {
        return switch (rule.matchType()) {
            case PHONE_PREFIX -> context.e164Phone() != null
                    && context.e164Phone().startsWith(rule.matchValue());
            case INSTITUTION_DOMAIN -> verifiedClaims(context) && domainMatches(rule.matchValue(), context);
            case OIDC_CLAIM -> verifiedClaims(context) && oidcClaimMatches(rule, context);
        };
    }

    private static boolean domainMatches(String domain, PlacementContext context) {
        String normalized = normalize(domain);
        if (context.affiliations() != null && context.affiliations().stream()
                .map(PolicyRoutingRule::normalize)
                .anyMatch(a -> a.equals(normalized) || a.endsWith("." + normalized))) {
            return true;
        }
        Map<String, String> attrs = attrs(context);
        return normalized.equals(normalize(attrs.get("email_domain")))
                || normalized.equals(normalize(attrs.get("hd")))
                || normalized.equals(normalize(attrs.get("institution_domain")));
    }

    private static boolean oidcClaimMatches(RoutingPolicyRule rule, PlacementContext context) {
        Map<String, String> attrs = attrs(context);
        if (rule.oidcIssuer() != null && !rule.oidcIssuer().isBlank()) {
            String issuer = attrs.getOrDefault("oidc_issuer", attrs.get("iss"));
            if (!rule.oidcIssuer().equalsIgnoreCase(nullToEmpty(issuer))) {
                return false;
            }
        }
        String claimName = rule.oidcClaim();
        if (claimName == null || claimName.isBlank()) {
            return false;
        }
        return normalize(rule.matchValue()).equals(normalize(attrs.get(claimName)));
    }

    private static Map<String, String> attrs(PlacementContext context) {
        return context.attributes() == null ? Map.of() : context.attributes();
    }

    private static boolean verifiedClaims(PlacementContext context) {
        return "true".equalsIgnoreCase(attrs(context).get(RoutingClaimsVerifier.VERIFIED_ATTRIBUTE));
    }

    private static String normalize(String s) {
        return nullToEmpty(s).trim().toLowerCase(Locale.ROOT);
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    @Override
    public int priority() {
        return 50;
    }
}
