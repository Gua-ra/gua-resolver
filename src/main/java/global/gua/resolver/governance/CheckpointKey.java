package global.gua.resolver.governance;

/**
 * A key listed in the witness list: the resolver's checkpoint key, or a witness key.
 *
 * @param url where the resolver serves its log, or where the witness publishes its signatures
 */
public record CheckpointKey(String keyId, String alg, String publicKey, String operatorId, Role role, String url) {

    public enum Role {
        RESOLVER,
        WITNESS
    }
}
