/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.time.Duration;
import java.time.Instant;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.roster.RosterStore;

/**
 * The ingest side of head verification: this node's roster, this node's clock, and the shared pure check.
 *
 * <p>It holds no rules of its own. Everything it decides lives in {@link AccountAuthorityHeadVerification},
 * which is also what the library verifier a client ports runs, so the node that accepts a head and the reader
 * that later checks one can never disagree about what a valid head is.
 *
 * <p>The roster it reads is {@link RosterStore#current()}, this node's verified view, so a member whose entry
 * the member-signature transition flag drops is not a publisher here either.
 */
@Component
@ConditionalOnExpression(AccountAuthorityFeature.ENABLED)
public class AccountAuthorityHeadVerifier {

    private final RosterStore rosterStore;
    private final Duration maxClockSkew;
    private final Duration maxValidity;

    public AccountAuthorityHeadVerifier(RosterStore rosterStore, ResolverProperties props) {
        this.rosterStore = rosterStore;
        this.maxClockSkew = props.getClaims().getMaxClockSkew();
        this.maxValidity = props.getAccountAuthority().getMaxValidity();
    }

    /** Decode, authenticate and time-check an envelope against the current roster, or refuse it. */
    public AccountAuthorityHeadVerification.Verified verify(AccountAuthorityHeadEnvelope envelope,
                                                           Instant now) {
        return AccountAuthorityHeadVerification.verify(
                envelope, rosterStore.current(), now, maxClockSkew, maxValidity);
    }
}
