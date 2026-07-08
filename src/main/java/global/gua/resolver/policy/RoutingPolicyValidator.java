package global.gua.resolver.policy;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.SignedRoster;

/** Structural and federation-boundary validation for routing-policy bundles. */
@Component
public class RoutingPolicyValidator {

    private final Clock clock;

    public RoutingPolicyValidator() {
        this(Clock.systemUTC());
    }

    RoutingPolicyValidator(Clock clock) {
        this.clock = clock;
    }

    public void validate(RoutingPolicyBundle bundle, SignedRoster roster) {
        if (bundle == null) {
            throw invalid("policy bundle is required");
        }
        if (!RoutingPolicyBundle.SCHEMA_VERSION.equals(bundle.schemaVersion())) {
            throw invalid("unsupported schemaVersion: " + bundle.schemaVersion());
        }
        if (blank(bundle.policyId())) {
            throw invalid("policyId is required");
        }
        if (bundle.version() <= 0) {
            throw invalid("version must be positive");
        }
        Instant now = Instant.now(clock);
        if (bundle.notBefore() != null && bundle.notBefore().isAfter(now)) {
            throw invalid("policy is not active yet");
        }
        if (bundle.expiresAt() != null && !bundle.expiresAt().isAfter(now)) {
            throw invalid("policy is expired");
        }

        Map<String, RosterEntry> activeHomeservers = roster.activeEntries().stream()
                .collect(Collectors.toMap(e -> e.homeserver().id(), Function.identity()));
        Map<String, DelegationZone> zones = validateZones(bundle.delegationZones(), activeHomeservers);
        validateRules(bundle.rules(), zones, activeHomeservers);
    }

    private Map<String, DelegationZone> validateZones(List<DelegationZone> zones,
                                                       Map<String, RosterEntry> activeHomeservers) {
        Map<String, DelegationZone> byId = new HashMap<>();
        for (DelegationZone zone : zones == null ? List.<DelegationZone>of() : zones) {
            if (blank(zone.id())) {
                throw invalid("delegation zone id is required");
            }
            if (byId.putIfAbsent(zone.id(), zone) != null) {
                throw invalid("duplicate delegation zone id: " + zone.id());
            }
            if (zone.scopeType() == null || blank(zone.scopeValue())) {
                throw invalid("delegation zone " + zone.id() + " requires scopeType and scopeValue");
            }
            if (blank(zone.delegateKeyId()) || blank(zone.delegatePublicKey())) {
                throw invalid("delegation zone " + zone.id()
                        + " requires delegateKeyId and delegatePublicKey (cryptographic delegation)");
            }
            if (zone.allowedHomeserverIds() == null || zone.allowedHomeserverIds().isEmpty()) {
                throw invalid("delegation zone " + zone.id() + " must allow at least one homeserver");
            }
            for (String homeserverId : zone.allowedHomeserverIds()) {
                if (!activeHomeservers.containsKey(homeserverId)) {
                    throw invalid("delegation zone " + zone.id()
                            + " references unknown or inactive homeserver " + homeserverId);
                }
            }
        }
        return byId;
    }

    private void validateRules(List<RoutingPolicyRule> rules, Map<String, DelegationZone> zones,
                               Map<String, RosterEntry> activeHomeservers) {
        Set<String> ids = new HashSet<>();
        Map<String, String> exactMatches = new HashMap<>();
        for (RoutingPolicyRule rule : rules == null ? List.<RoutingPolicyRule>of() : rules) {
            if (blank(rule.id())) {
                throw invalid("rule id is required");
            }
            if (!ids.add(rule.id())) {
                throw invalid("duplicate rule id: " + rule.id());
            }
            if (!rule.isEnabled()) {
                continue;
            }
            if (rule.matchType() == null || blank(rule.matchValue())) {
                throw invalid("rule " + rule.id() + " requires matchType and matchValue");
            }
            if (blank(rule.targetHomeserverId()) || !activeHomeservers.containsKey(rule.targetHomeserverId())) {
                throw invalid("rule " + rule.id() + " targets unknown or inactive homeserver "
                        + rule.targetHomeserverId());
            }
            DelegationZone zone = zones.get(rule.delegatedZoneId());
            if (blank(rule.delegatedZoneId()) || zone == null) {
                throw invalid("rule " + rule.id() + " must reference an explicit delegation zone");
            }
            if (!zone.allowedHomeserverIds().contains(rule.targetHomeserverId())) {
                throw invalid("rule " + rule.id() + " targets homeserver outside delegation zone "
                        + zone.id());
            }
            if (!withinZone(rule, zone)) {
                throw invalid("rule " + rule.id() + " match is outside delegation zone " + zone.id());
            }
            String matchKey = rule.matchType().name() + ":" + normalize(rule.matchValue());
            String previousTarget = exactMatches.putIfAbsent(matchKey, rule.targetHomeserverId());
            if (previousTarget != null && !previousTarget.equals(rule.targetHomeserverId())) {
                throw invalid("ambiguous rules for " + matchKey + ": " + previousTarget
                        + " and " + rule.targetHomeserverId());
            }
        }
    }

    private static boolean withinZone(RoutingPolicyRule rule, DelegationZone zone) {
        return switch (rule.matchType()) {
            case PHONE_PREFIX -> zone.scopeType() == DelegationZone.ScopeType.PHONE_PREFIX
                    && rule.matchValue().startsWith(zone.scopeValue());
            case INSTITUTION_DOMAIN -> zone.scopeType() == DelegationZone.ScopeType.INSTITUTION_DOMAIN
                    && domainWithin(rule.matchValue(), zone.scopeValue());
            case OIDC_CLAIM -> zone.scopeType() == DelegationZone.ScopeType.OIDC_ISSUER
                    && rule.oidcIssuer() != null
                    && rule.oidcIssuer().equalsIgnoreCase(zone.scopeValue());
        };
    }

    private static boolean domainWithin(String domain, String parent) {
        String d = normalize(domain);
        String p = normalize(parent);
        return d.equals(p) || d.endsWith("." + p);
    }

    private static String normalize(String s) {
        return s == null ? "" : s.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    private static RoutingPolicyValidationException invalid(String message) {
        return new RoutingPolicyValidationException(message);
    }

    public static class RoutingPolicyValidationException extends RuntimeException {
        public RoutingPolicyValidationException(String message) {
            super(message);
        }
    }
}
