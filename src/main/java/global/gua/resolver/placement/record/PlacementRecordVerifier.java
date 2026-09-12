package global.gua.resolver.placement.record;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;

/**
 * Makes a presented placement record self-authenticating, which is the whole reason the ingest endpoint can
 * be public (ADM-008 decision 7).
 *
 * <p>The record names a homeserver. That homeserver must be an ACTIVE entry of the current verified roster,
 * and the signature must verify under that entry's roster signing key, the key whose possession admission
 * proved. A signature by any other member is rejected, so the bound on what a caller who can reach this
 * endpoint can do is: present records, each of which either verifies under an active roster key or is
 * refused. No part of this check consults the placement table, so a caller learns nothing about stored state
 * by failing it.
 *
 * <p>The validity window is checked against this node's own clock with the configured claims skew. ADM-008
 * records that as admission rather than a replayable transition (ADM-001 L11): these windows move to
 * sequenced time when placements enter the state root.
 */
@Component
@ConditionalOnExpression(PlacementFeature.ENABLED)
public class PlacementRecordVerifier {

    private final RosterStore rosterStore;
    private final Duration maxClockSkew;
    private final Duration maxValidity;

    public PlacementRecordVerifier(RosterStore rosterStore, ResolverProperties props) {
        this.rosterStore = rosterStore;
        this.maxClockSkew = props.getClaims().getMaxClockSkew();
        this.maxValidity = props.getPlacement().getMaxValidity();
    }

    /** A record that passed every check, with the exact bytes and signature it arrived as. */
    public record Verified(PlacementRecord record, PlacementRecordEnvelope envelope) {}

    /**
     * Decode, authenticate and time-check an envelope, or refuse it with one reason. The checks run in a
     * fixed order: the shape of the bytes, then the roster, then the signature, then the clock. Nothing
     * before the signature reads stored placement state, and nothing after it is reached without a member
     * key.
     */
    public Verified verify(PlacementRecordEnvelope envelope, Instant now) {
        if (envelope == null
                || envelope.record() == null || envelope.record().isBlank()
                || envelope.signature() == null || envelope.signature().isBlank()) {
            throw new PlacementRecordException(PlacementRecordRejection.MALFORMED_ENVELOPE);
        }

        byte[] canonical;
        try {
            canonical = Base64.getUrlDecoder().decode(envelope.record());
        } catch (IllegalArgumentException e) {
            throw new PlacementRecordException(PlacementRecordRejection.BAD_BASE64);
        }

        PlacementRecord record = PlacementRecordCodec.decode(canonical);

        RosterEntry entry = rosterEntry(record.homeserverId());
        if (entry == null) {
            throw new PlacementRecordException(PlacementRecordRejection.UNKNOWN_HOMESERVER);
        }
        // A member that used to be ACTIVE is refused exactly like one that never was: the roster is read at
        // acceptance time, not at issuance time.
        if (!entry.isActive()) {
            throw new PlacementRecordException(PlacementRecordRejection.HOMESERVER_NOT_ACTIVE);
        }

        PublicKey signingKey;
        try {
            signingKey = Ed25519.publicKey(entry.homeserver().signingKey());
        } catch (IllegalArgumentException e) {
            throw new PlacementRecordException(PlacementRecordRejection.SIGNER_KEY_UNUSABLE);
        }
        if (!Ed25519.verify(signingKey, canonical, envelope.signature())) {
            throw new PlacementRecordException(PlacementRecordRejection.BAD_SIGNATURE);
        }

        checkWindow(record, now);
        return new Verified(record, envelope);
    }

    /**
     * The roster entry for this id, ACTIVE or not, from the node's verified view. An entry the member-
     * signature transition flag drops is not in that view at all and reads here as unknown, which is the
     * same answer the roster itself gives for it.
     */
    private RosterEntry rosterEntry(String homeserverId) {
        return rosterStore.current().entries().stream()
                .filter(e -> e.homeserver().id().equals(homeserverId))
                .findFirst()
                .orElse(null);
    }

    private void checkWindow(PlacementRecord record, Instant now) {
        if (Duration.between(record.notBefore(), record.notAfter()).compareTo(maxValidity) > 0) {
            throw new PlacementRecordException(PlacementRecordRejection.WINDOW_TOO_LONG);
        }
        if (now.plus(maxClockSkew).isBefore(record.notBefore())) {
            throw new PlacementRecordException(PlacementRecordRejection.NOT_YET_VALID);
        }
        if (now.minus(maxClockSkew).isAfter(record.notAfter())) {
            throw new PlacementRecordException(PlacementRecordRejection.EXPIRED);
        }
        // A far-future issuedAt would otherwise let one record freeze an account's slot against every later
        // re-issue, since the re-issue rule compares on issuedAt.
        if (record.issuedAt().isAfter(now.plus(maxClockSkew))) {
            throw new PlacementRecordException(PlacementRecordRejection.ISSUED_IN_THE_FUTURE);
        }
    }
}
