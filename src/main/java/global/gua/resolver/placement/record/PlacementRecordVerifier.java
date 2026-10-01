/*
 * Copyright 2026 Gua
 */
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

/** A record must verify under the roster key of the ACTIVE homeserver it names. */
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

    public record Verified(PlacementRecord record, PlacementRecordEnvelope envelope) {}

    public Verified verify(PlacementRecordEnvelope envelope, Instant now) {
        if (envelope == null
                || envelope.record() == null || envelope.record().isBlank()
                || envelope.signature() == null || envelope.signature().isBlank()) {
            throw new PlacementRecordException(PlacementRecordRejection.MALFORMED_ENVELOPE);
        }

        byte[] canonical = decodeCanonicalBase64Url(envelope.record());

        PlacementRecord record = PlacementRecordCodec.decode(canonical);

        RosterEntry entry = rosterEntry(record.homeserverId());
        if (entry == null) {
            throw new PlacementRecordException(PlacementRecordRejection.UNKNOWN_HOMESERVER);
        }
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

    private static byte[] decodeCanonicalBase64Url(String value) {
        if (value.indexOf('=') >= 0) {
            throw new PlacementRecordException(PlacementRecordRejection.BAD_BASE64);
        }
        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new PlacementRecordException(PlacementRecordRejection.BAD_BASE64);
        }
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value)) {
            throw new PlacementRecordException(PlacementRecordRejection.BAD_BASE64);
        }
        return decoded;
    }

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
        // A far-future issuedAt would block every later re-issue, which compares on issuedAt.
        if (record.issuedAt().isAfter(now.plus(maxClockSkew))) {
            throw new PlacementRecordException(PlacementRecordRejection.ISSUED_IN_THE_FUTURE);
        }
    }
}
