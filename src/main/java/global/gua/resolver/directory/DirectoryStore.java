package global.gua.resolver.directory;

import java.util.Optional;

/** No HTTP write path. Phones are addressed only by peppered HMAC, and there is no scan or export method. */
public interface DirectoryStore {

    Optional<String> homeserverIdForPhone(String e164Phone);

    Optional<String> homeserverIdForPhoneHash(String phoneHash);

    Optional<String> homeserverIdForUsername(String username);

    void putPhone(String e164Phone, String homeserverId);

    void putUsername(String username, String homeserverId);

    void removePhone(String e164Phone);
}
