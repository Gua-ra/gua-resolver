package global.gua.resolver.governance;

public record GovernanceKey(String keyId, String alg, String publicKey, String operatorId) {

    public static final String ALG = "Ed25519";
}
