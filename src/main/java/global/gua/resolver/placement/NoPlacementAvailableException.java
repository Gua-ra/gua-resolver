package global.gua.resolver.placement;

/**
 * Thrown when no placement rule (including the weighted fallback) can yield a homeserver, e.g. every active
 * roster entry has {@code acceptsNew=false}, or their weights add up past the fallback's limit. This is an
 * operational unavailability, not a server bug, so the API maps it to 503 rather than 500.
 */
public class NoPlacementAvailableException extends RuntimeException {
    public NoPlacementAvailableException(String message) {
        super(message);
    }
}
