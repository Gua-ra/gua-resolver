package global.gua.resolver.governance;

import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

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

    /** Policy bundle verification counts these per key, not per operator. */
    public List<ResolverProperties.TrustedKey> asTrustedKeys() {
        return byKeyId.values().stream().map(k -> {
            ResolverProperties.TrustedKey trusted = new ResolverProperties.TrustedKey();
            trusted.setId(k.keyId());
            trusted.setPublicKey(k.publicKey());
            return trusted;
        }).toList();
    }

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
