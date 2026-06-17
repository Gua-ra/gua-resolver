package global.gua.resolver.directory;

import java.util.Optional;

/**
 * The shared, persistent phone/username → homeserver directory (§4). Each homeserver is the authoritative
 * writer for its own accounts; the resolver front door reads it to route an existing account to its home.
 *
 * <p>Privacy invariants: phones are addressed only by {@link PhoneHasher peppered HMAC}, never raw; there
 * is no list/scan/bulk-export method by design (mirrors query, they don't replicate the phone graph).
 */
public interface DirectoryStore {

    /** Homeserver id hosting the account for this E.164 phone, if any. */
    Optional<String> homeserverIdForPhone(String e164Phone);

    /** Homeserver id for an already-peppered phone hash (the lookup primitive a mirror queries by). */
    Optional<String> homeserverIdForPhoneHash(String phoneHash);

    /** Homeserver id hosting this global username, if any. */
    Optional<String> homeserverIdForUsername(String username);

    /** Upsert the phone→homeserver mapping (called by the hosting homeserver at account provisioning). */
    void putPhone(String e164Phone, String homeserverId);

    /** Upsert the username→homeserver mapping. */
    void putUsername(String username, String homeserverId);

    /** Remove a phone mapping (account deletion / migration); idempotent. */
    void removePhone(String e164Phone);
}
