package global.gua.resolver.service;

/**
 * The directory maps the phone to a homeserver that is not ACTIVE in the verified roster (suspended, revoked
 * or removed). The account exists, so callers must fail and never treat it as a new account.
 */
public class HomeserverUnavailableException extends RuntimeException {

    private final String homeserverId;

    public HomeserverUnavailableException(String homeserverId) {
        super("homeserver " + homeserverId + " is not active in the roster");
        this.homeserverId = homeserverId;
    }

    public String homeserverId() {
        return homeserverId;
    }
}
