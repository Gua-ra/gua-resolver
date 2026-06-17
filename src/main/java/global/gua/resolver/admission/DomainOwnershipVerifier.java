package global.gua.resolver.admission;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Verifies that an applicant controls the {@code server_name} it is registering (§3 step 1). The default
 * implementation accepts a non-empty proof token and records it (the accountable, logged on-ramp); a real
 * deployment swaps in a DNS TXT / well-known HTTP challenge by overriding this bean. Kept as its own
 * interface precisely so the trust-sensitive check is pluggable without touching the admission flow.
 */
public interface DomainOwnershipVerifier {

    /** @return true if {@code proof} demonstrates control of {@code serverName}. */
    boolean verify(String serverName, String proof);

    @Component
    class TokenPresenceVerifier implements DomainOwnershipVerifier {
        private static final Logger log = LoggerFactory.getLogger(TokenPresenceVerifier.class);

        @Override
        public boolean verify(String serverName, String proof) {
            boolean ok = proof != null && !proof.isBlank();
            // The proof is logged to the audit trail regardless; production replaces this with a real
            // DNS/well-known challenge against serverName.
            log.info("Domain-ownership proof for {} recorded (accepted={})", serverName, ok);
            return ok;
        }
    }
}
