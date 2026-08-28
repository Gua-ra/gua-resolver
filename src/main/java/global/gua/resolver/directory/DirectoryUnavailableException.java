package global.gua.resolver.directory;

/** Raised when a mirror cannot query the authority directory and fail-closed mode is active. */
public class DirectoryUnavailableException extends RuntimeException {
    public DirectoryUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
