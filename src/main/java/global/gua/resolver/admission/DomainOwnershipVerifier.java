package global.gua.resolver.admission;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** The default implementation accepts any non-empty proof; a real deployment must override this bean. */
public interface DomainOwnershipVerifier {

    boolean verify(String serverName, String proof);

    @Component
    class TokenPresenceVerifier implements DomainOwnershipVerifier {
        private static final Logger log = LoggerFactory.getLogger(TokenPresenceVerifier.class);

        @Override
        public boolean verify(String serverName, String proof) {
            boolean ok = proof != null && !proof.isBlank();
            log.info("Domain-ownership proof for {} recorded (accepted={})", serverName, ok);
            return ok;
        }
    }
}
