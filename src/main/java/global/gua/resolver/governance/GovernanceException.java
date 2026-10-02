package global.gua.resolver.governance;

/**
 * A governance object that is refused: it does not parse strictly, does not encode canonically, does not
 * carry enough signatures from distinct operators, or does not continue the chain it claims to. Refused,
 * never repaired: a governance object the resolver cannot fully verify has no partial meaning.
 */
public class GovernanceException extends RuntimeException {

    public GovernanceException(String message) {
        super(message);
    }
}
