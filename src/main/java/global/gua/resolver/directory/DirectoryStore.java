package global.gua.resolver.directory;

import java.util.Optional;

/**
 * The persistent phone/username to homeserver directory. It has no HTTP write path: the write methods below
 * are an internal API (tests seed rows with them) and no controller calls them. The resolver reads the rows
 * to route an existing account.
 *
 * <p>Privacy: phones are addressed only by {@link PhoneHasher peppered HMAC}, never raw, and there is no
 * list, scan or bulk-export method (mirrors query rows one at a time; they do not replicate the directory).
 */
public interface DirectoryStore {

    /** Homeserver id hosting the account for this E.164 phone, if any. */
    Optional<String> homeserverIdForPhone(String e164Phone);

    /** Homeserver id for an already-peppered phone hash (the lookup primitive a mirror queries by). */
    Optional<String> homeserverIdForPhoneHash(String phoneHash);

    /** Homeserver id hosting this global username, if any. */
    Optional<String> homeserverIdForUsername(String username);

    /** Upsert a phone to homeserver row. Internal API only: no HTTP path reaches it. */
    void putPhone(String e164Phone, String homeserverId);

    /** Upsert the username to homeserver mapping. */
    void putUsername(String username, String homeserverId);

    /** Remove a phone mapping (account deletion / migration); idempotent. */
    void removePhone(String e164Phone);
}
