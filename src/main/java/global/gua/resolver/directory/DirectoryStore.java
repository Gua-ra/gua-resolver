package global.gua.resolver.directory;

import java.util.Optional;

/**
 * The persistent phone/username to homeserver directory. It has no HTTP write path: the member-written
 * {@code POST /directory/entries} was removed (ADM-001 L1b). The write methods below are an internal API
 * (tests seed rows with them, and the placement work will need writers); no controller calls them. Rows
 * written before the removal stay, and the resolver reads them to route an existing account, until
 * attested binding records replace them (ADM-001 L7).
 *
 * <p>Privacy: phones are addressed only by {@link PhoneHasher peppered HMAC}, never raw, and there is no
 * list/scan/bulk-export method (mirrors query rows one at a time; they do not replicate the directory).
 * The shared pepper is scheduled for replacement (ADM-001 L15).
 */
public interface DirectoryStore {

    /** Homeserver id hosting the account for this E.164 phone, if any. */
    Optional<String> homeserverIdForPhone(String e164Phone);

    /** Homeserver id for an already-peppered phone hash (the lookup primitive a mirror queries by). */
    Optional<String> homeserverIdForPhoneHash(String phoneHash);

    /** Homeserver id hosting this global username, if any. */
    Optional<String> homeserverIdForUsername(String username);

    /**
     * Upsert a phone→homeserver row. Internal API only: no HTTP path reaches it (ADM-001 L1b). ADM-001 L7
     * replaces these rows with attested binding records.
     */
    void putPhone(String e164Phone, String homeserverId);

    /** Upsert the username→homeserver mapping. */
    void putUsername(String username, String homeserverId);

    /** Remove a phone mapping (account deletion / migration); idempotent. */
    void removePhone(String e164Phone);
}
