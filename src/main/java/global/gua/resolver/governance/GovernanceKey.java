package global.gua.resolver.governance;

/**
 * One governance key enumerated by a {@link FederationGenesis} or installed by a
 * {@link GovernanceTransition}.
 *
 * <p>{@code operatorId} is what a threshold counts. Different keys are not independence, so every key
 * records the operator that holds it and {@link GovernanceVerifier} dedupes on that, never on
 * {@code keyId}. With one operator the count is 1 no matter how many keys are listed.
 *
 * @param keyId     stable label naming exactly one key
 * @param alg       {@code Ed25519}
 * @param publicKey the Ed25519 public key, base64 X.509 SubjectPublicKeyInfo
 * @param operatorId the trust domain that holds this key; the unit a governance threshold counts
 */
public record GovernanceKey(String keyId, String alg, String publicKey, String operatorId) {

    public static final String ALG = "Ed25519";
}
