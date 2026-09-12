package global.gua.resolver.governance;

import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

/**
 * The governance keys in force: the genesis key set with every valid transition applied, plus the threshold
 * that applies with them.
 *
 * <p>It holds keys and answers lookups; it does not count votes. The counting rule lives in
 * {@link GovernanceVerifier} precisely because it is the part ADM-001 L8 constrains, and keeping it in one
 * place is what stops a future caller from reaching for
 * {@code RosterVerifier.countValidSignatures} and reintroducing per-key counting.
 */
public final class GovernanceKeySet {

    private final String genesisId;
    private final long threshold;
    private final Map<String, GovernanceKey> byKeyId;
    private final Map<String, PublicKey> publicKeys;

    private GovernanceKeySet(String genesisId, long threshold, Map<String, GovernanceKey> byKeyId,
                             Map<String, PublicKey> publicKeys) {
        this.genesisId = genesisId;
        this.threshold = threshold;
        this.byKeyId = Map.copyOf(byKeyId);
        this.publicKeys = Map.copyOf(publicKeys);
    }

    public static GovernanceKeySet of(String genesisId, long threshold, List<GovernanceKey> keys) {
        validateKeys(keys, threshold);
        Map<String, GovernanceKey> byId = new LinkedHashMap<>();
        Map<String, PublicKey> parsed = new LinkedHashMap<>();
        for (GovernanceKey key : keys) {
            byId.put(key.keyId(), key);
            parsed.put(key.keyId(), Ed25519.publicKey(key.publicKey()));
        }
        return new GovernanceKeySet(genesisId, threshold, byId, parsed);
    }

    public String genesisId() {
        return genesisId;
    }

    public long threshold() {
        return threshold;
    }

    public List<GovernanceKey> keys() {
        return List.copyOf(byKeyId.values());
    }

    /** The distinct operators holding these keys: the population a threshold is counted against. */
    public Set<String> operators() {
        return byKeyId.values().stream().map(GovernanceKey::operatorId)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    GovernanceKey key(String keyId) {
        return byKeyId.get(keyId);
    }

    PublicKey publicKey(String keyId) {
        return publicKeys.get(keyId);
    }

    /**
     * These keys as a trusted-key list, so the policy bundle verifier can check bundles against the
     * governance root instead of against the operational authority key. Policy bundles keep the shipped
     * envelope and its per-key counting in v1; that is tolerable only because it is a single-operator key
     * set today and because no independence claim rests on it. A threshold that has to mean independence
     * goes through {@link GovernanceVerifier}.
     */
    public List<ResolverProperties.TrustedKey> asTrustedKeys() {
        return byKeyId.values().stream().map(k -> {
            ResolverProperties.TrustedKey trusted = new ResolverProperties.TrustedKey();
            trusted.setId(k.keyId());
            trusted.setPublicKey(k.publicKey());
            return trusted;
        }).toList();
    }

    /**
     * Structural validation of a key set and the threshold that goes with it. A threshold higher than the
     * number of distinct operators is refused at load rather than at first use: it can never be satisfied
     * honestly, and the failure should be a startup error an operator sees, not a governance act that
     * silently cannot happen.
     */
    static void validateKeys(List<GovernanceKey> keys, long threshold) {
        if (keys == null || keys.isEmpty()) {
            throw new GovernanceException("a governance key set needs at least one key");
        }
        if (threshold < 1) {
            throw new GovernanceException("governance threshold must be at least 1");
        }
        Set<String> keyIds = new java.util.HashSet<>();
        Set<String> operators = new java.util.HashSet<>();
        for (GovernanceKey key : keys) {
            if (key == null || key.keyId() == null || key.keyId().isBlank()) {
                throw new GovernanceException("every governance key needs a keyId");
            }
            if (!GovernanceKey.ALG.equals(key.alg())) {
                throw new GovernanceException(
                        "unsupported governance key alg for " + key.keyId() + ": " + key.alg());
            }
            if (key.operatorId() == null || key.operatorId().isBlank()) {
                throw new GovernanceException("governance key " + key.keyId()
                        + " needs an operatorId: a threshold counts operators, not keys (ADM-001 L8)");
            }
            if (!keyIds.add(key.keyId())) {
                throw new GovernanceException("duplicate governance keyId: " + key.keyId());
            }
            try {
                Ed25519.publicKey(key.publicKey());
            } catch (RuntimeException e) {
                throw new GovernanceException(
                        "governance key " + key.keyId() + " is not an Ed25519 public key");
            }
            operators.add(key.operatorId());
        }
        if (threshold > operators.size()) {
            throw new GovernanceException("governance threshold " + threshold + " exceeds the "
                    + operators.size() + " distinct operator(s) holding these keys, so it can never be met");
        }
    }
}
