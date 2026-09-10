package global.gua.resolver.directory;

import java.util.Optional;

/**
 * The persistent phone/username to homeserver directory, written by federation members through
 * {@code POST /directory/entries}. Any ACTIVE member key can write any row; the store does not check
 * that the writer hosts the account. The resolver reads it to route an existing account. This
 * member-written directory is scheduled for removal (ADM-001 L1b) in favour of attested binding records
 * (ADM-001 L7).
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
     * Upsert a phone→homeserver row of the member-written directory. ADM-001 L1b removes this directory and
     * L7 replaces it with attested binding records.
     */
    void putPhone(String e164Phone, String homeserverId);

    /** Upsert the username→homeserver mapping. */
    void putUsername(String username, String homeserverId);

    /** Remove a phone mapping (account deletion / migration); idempotent. */
    void removePhone(String e164Phone);
}
