/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.SignedRoster;

/**
 * What makes a presented authority head self-authenticating, as one pure function.
 *
 * <p>The head object names a homeserver. That homeserver must be an ACTIVE entry of a verified roster, and the
 * signature must verify under that entry's roster signing key, the key whose possession admission proved. A
 * signature by any other member is refused, so the bound on what a caller who can reach the ingest endpoint
 * can do is: present head objects, each of which either verifies under an active roster key or is refused.
 *
 * <p>This class exists so the resolver's ingest and the library verifier a client ports cannot diverge: the
 * node that accepts a head and the reader that later checks one run the same code over the same bytes. It
 * reads no stored state and no clock of its own, which is what lets the ingest endpoint be public
 * (ADM-008 decision 7, the same argument as for placement records).
 *
 * <p>The roster is read at the time the caller passes, not at the head's issuance time: a member that used to
 * be ACTIVE is refused exactly like one that never was.
 */
public final class AccountAuthorityHeadVerification {

    private AccountAuthorityHeadVerification() {}

    /** A head that passed every byte, roster, signature and window check, with the bytes it arrived as. */
    public record Verified(AccountAuthorityHead head, AccountAuthorityHeadEnvelope envelope,
                           byte[] canonical) {}

    /**
     * Decode, authenticate and time-check an envelope against a roster, or refuse it with one reason.
     *
     * <p>The checks run in a fixed order: the shape of the bytes, then the roster, then the signature, then
     * the clock. Nothing before the signature check consults anything but the presented bytes and the roster.
     *
     * @param envelope     the transport pair, exactly as it arrived
     * @param roster       an already-verified roster; the caller owns the k-of-n check
     * @param now          the acceptance (or reading) time the window is checked against
     * @param maxClockSkew how far the two clocks may disagree
     * @param maxValidity  the longest window a head object may claim
     */
    public static Verified verify(AccountAuthorityHeadEnvelope envelope, SignedRoster roster, Instant now,
                                 Duration maxClockSkew, Duration maxValidity) {
        if (envelope == null
                || envelope.record() == null || envelope.record().isBlank()
                || envelope.signature() == null || envelope.signature().isBlank()) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.MALFORMED_ENVELOPE);
        }

        byte[] canonical = decodeCanonicalBase64Url(envelope.record());
        AccountAuthorityHead head = AccountAuthorityHeadCodec.decode(canonical);

        RosterEntry entry = entry(roster, head.homeserverId());
        if (entry == null) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.UNKNOWN_HOMESERVER);
        }
        if (!entry.isActive()) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.HOMESERVER_NOT_ACTIVE);
        }

        PublicKey signingKey;
        try {
            signingKey = Ed25519.publicKey(entry.homeserver().signingKey());
        } catch (IllegalArgumentException e) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.SIGNER_KEY_UNUSABLE);
        }
        if (!Ed25519.verify(signingKey, canonical, envelope.signature())) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.BAD_SIGNATURE);
        }

        checkWindow(head, now, maxClockSkew, maxValidity);
        return new Verified(head, envelope, canonical);
    }

    /**
     * The one accepted spelling of the record field: unpadded base64url that re-encodes to exactly what
     * arrived.
     *
     * <p>A plain decoder accepts padding and ignores the trailing bits of the last character, so one byte
     * string would have several spellings. The signature covers the bytes and not the spelling, so every
     * spelling of a signed head would verify, and a publisher retrying after a timeout with a differently
     * spelled but byte-identical head would be read as a new publication rather than as the same one. The
     * check is decode, re-encode, and require the result to equal the input, exactly as the accountId's own
     * canonical check works.
     */
    public static byte[] decodeCanonicalBase64Url(String value) {
        if (value.indexOf('=') >= 0) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.BAD_BASE64);
        }
        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.BAD_BASE64);
        }
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value)) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.BAD_BASE64);
        }
        return decoded;
    }

    /** The roster entry for this id, ACTIVE or not; an entry the roster does not carry reads as unknown. */
    private static RosterEntry entry(SignedRoster roster, String homeserverId) {
        if (roster == null || roster.entries() == null) {
            return null;
        }
        return roster.entries().stream()
                .filter(e -> e.homeserver() != null && homeserverId.equals(e.homeserver().id()))
                .findFirst()
                .orElse(null);
    }

    private static void checkWindow(AccountAuthorityHead head, Instant now, Duration maxClockSkew,
                                    Duration maxValidity) {
        if (Duration.between(head.notBefore(), head.notAfter()).compareTo(maxValidity) > 0) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.WINDOW_TOO_LONG);
        }
        if (now.plus(maxClockSkew).isBefore(head.notBefore())) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.NOT_YET_VALID);
        }
        // An expired head is the staleness signal, not a forgery: it is how a reader sees that its homeserver
        // stopped publishing, which is the one part of withholding this phase can make visible (ADM-005
        // requirement 9 owns the rest).
        if (now.minus(maxClockSkew).isAfter(head.notAfter())) {
            throw new AccountAuthorityHeadException(AccountAuthorityHeadRejection.EXPIRED);
        }
        if (head.issuedAt().isAfter(now.plus(maxClockSkew))) {
            throw new AccountAuthorityHeadException(
                    AccountAuthorityHeadRejection.ISSUED_IN_THE_FUTURE);
        }
    }
}
