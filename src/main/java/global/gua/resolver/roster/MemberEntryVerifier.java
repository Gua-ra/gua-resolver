package global.gua.resolver.roster;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;

/**
 * Verifies a member's self-signature over its roster entry (ADM-007, brief rules 1.4). Stateless: the caller
 * passes the acceptance time and, when it has one, the last entry it accepted for the same homeserver id.
 *
 * <ol>
 *   <li>The block names {@code gua-member-entry.v1} and {@code Ed25519}.</li>
 *   <li>The canonical bytes are recomputed from the transported fields; a field with no canonical encoding
 *       refuses the entry.</li>
 *   <li>A signature whose key id equals {@code member.keyId} verifies under {@code homeserver.signingKey}.</li>
 *   <li>The acceptance time lies in {@code [notBefore, notAfter]}, the window is positive, at millisecond
 *       precision, and no longer than the configured maximum lifetime.</li>
 *   <li>With a prior entry: the sequence never goes backwards, one sequence names one entry, and a changed
 *       signing key must also be signed by the previous key under a new key id (rotation).</li>
 * </ol>
 * A failure is reported, never repaired; what the caller does with it (drop, count, reject) is its policy.
 */
public final class MemberEntryVerifier {

    public static final Duration DEFAULT_MAX_LIFETIME = Duration.ofDays(400);

    public enum Outcome { VALID, UNATTESTED, INVALID }

    /**
     * The last entry a verifier accepted for a homeserver id.
     *
     * @param keyId      its key id, or null when the entry was never attested (a legacy or seeded entry)
     * @param signingKey its signing key (base64 X.509)
     * @param sequence   its sequence, 0 when never attested
     * @param entryHash  SHA-256 hex of its canonical bytes, or null when never attested
     */
    public record Prior(String keyId, String signingKey, long sequence, String entryHash) {}

    /** @param entryHash SHA-256 hex of the canonical bytes when they could be computed, else null */
    public record Result(Outcome outcome, String reason, String entryHash) {
        public boolean valid() {
            return outcome == Outcome.VALID;
        }

        static Result ok(String hash) {
            return new Result(Outcome.VALID, null, hash);
        }

        static Result unattested() {
            return new Result(Outcome.UNATTESTED, "no member attestation", null);
        }

        static Result invalid(String reason, String hash) {
            return new Result(Outcome.INVALID, reason, hash);
        }
    }

    private final Duration maxLifetime;

    public MemberEntryVerifier(Duration maxLifetime) {
        this.maxLifetime = (maxLifetime == null || maxLifetime.isNegative() || maxLifetime.isZero())
                ? DEFAULT_MAX_LIFETIME
                : maxLifetime;
    }

    public Duration maxLifetime() {
        return maxLifetime;
    }

    public Result verify(RosterEntry entry, Instant at, Prior prior) {
        return verify(entry.homeserver(), entry.member(), at, prior);
    }

    public Result verify(Homeserver homeserver, MemberAttestation member, Instant at) {
        return verify(homeserver, member, at, null);
    }

    public Result verify(Homeserver homeserver, MemberAttestation member, Instant at, Prior prior) {
        if (member == null) {
            return Result.unattested();
        }
        if (!CanonicalMemberEntry.SCHEMA.equals(member.schema())) {
            return Result.invalid("unsupported schema: " + member.schema(), null);
        }
        if (!CanonicalMemberEntry.ALG.equals(member.alg())) {
            return Result.invalid("unsupported alg: " + member.alg(), null);
        }
        if (member.keyId() == null || member.keyId().isBlank()) {
            return Result.invalid("keyId is required", null);
        }
        if (member.sequence() < 1) {
            return Result.invalid("sequence must be at least 1", null);
        }
        String window = checkWindow(member, at);
        if (window != null) {
            return Result.invalid(window, null);
        }
        String signatureShape = checkSignatureShape(member);
        if (signatureShape != null) {
            return Result.invalid(signatureShape, null);
        }

        byte[] canonical;
        try {
            canonical = CanonicalMemberEntry.bytes(homeserver, member);
        } catch (CanonicalEncoder.CanonicalEncodingException e) {
            return Result.invalid("no canonical encoding: " + e.getMessage(), null);
        }
        String hash = CanonicalEncoder.sha256Hex(canonical);

        PublicKey key = publicKey(homeserver.signingKey());
        if (key == null) {
            return Result.invalid("signingKey is not an Ed25519 public key", hash);
        }
        MemberSignature own = member.signatures().stream()
                .filter(s -> member.keyId().equals(s.keyId())).findFirst().orElse(null);
        if (own == null) {
            return Result.invalid("no signature by keyId " + member.keyId(), hash);
        }
        if (!Ed25519.verify(key, canonical, own.signatureB64())) {
            return Result.invalid("signature by keyId " + member.keyId() + " does not verify", hash);
        }

        if (prior != null) {
            String continuity = checkContinuity(homeserver, member, prior, canonical, hash);
            if (continuity != null) {
                return Result.invalid(continuity, hash);
            }
        }
        return Result.ok(hash);
    }

    private String checkWindow(MemberAttestation member, Instant at) {
        Instant notBefore = member.notBefore();
        Instant notAfter = member.notAfter();
        if (notBefore == null || notAfter == null) {
            return "notBefore and notAfter are required";
        }
        if (notBefore.getNano() % 1_000_000 != 0 || notAfter.getNano() % 1_000_000 != 0) {
            return "notBefore and notAfter must have millisecond precision";
        }
        if (!notAfter.isAfter(notBefore)) {
            return "notAfter must be after notBefore";
        }
        if (Duration.between(notBefore, notAfter).compareTo(maxLifetime) > 0) {
            return "validity window exceeds the maximum lifetime of " + maxLifetime.toDays() + " days";
        }
        if (at.isBefore(notBefore)) {
            return "not valid before " + notBefore;
        }
        if (at.isAfter(notAfter)) {
            return "expired at " + notAfter;
        }
        return null;
    }

    private static String checkSignatureShape(MemberAttestation member) {
        if (member.signatures().isEmpty()) {
            return "no signatures";
        }
        Set<String> seen = new HashSet<>();
        for (MemberSignature s : member.signatures()) {
            if (s == null || s.keyId() == null || s.keyId().isBlank() || s.signatureB64() == null) {
                return "malformed signature element";
            }
            if (!seen.add(s.keyId())) {
                return "duplicate signature keyId " + s.keyId();
            }
        }
        return null;
    }

    private static String checkContinuity(Homeserver homeserver, MemberAttestation member, Prior prior,
                                          byte[] canonical, String hash) {
        boolean keyChanged = !homeserver.signingKey().equals(prior.signingKey());
        if (member.sequence() < prior.sequence()) {
            return "sequence regression: " + member.sequence() + " after " + prior.sequence();
        }
        if (member.sequence() == prior.sequence()) {
            if (keyChanged) {
                return "a signing key change needs a higher sequence";
            }
            if (prior.entryHash() != null && !prior.entryHash().equals(hash)) {
                return "sequence " + member.sequence() + " already names a different entry";
            }
            return null;
        }
        if (!keyChanged) {
            return null;
        }
        // Rotation: the previous key must sign the same bytes, and the new key gets its own id.
        if (prior.keyId() != null && prior.keyId().equals(member.keyId())) {
            return "a rotated key needs a new keyId";
        }
        PublicKey previous = publicKey(prior.signingKey());
        if (previous == null) {
            return "no previous key to authorise a key rotation";
        }
        boolean signedByPrevious = member.signatures().stream()
                .filter(s -> prior.keyId() != null
                        ? prior.keyId().equals(s.keyId())
                        : !member.keyId().equals(s.keyId()))
                .anyMatch(s -> Ed25519.verify(previous, canonical, s.signatureB64()));
        return signedByPrevious ? null : "key rotation is not signed by the previous key";
    }

    private static PublicKey publicKey(String base64) {
        if (base64 == null || base64.isBlank()) {
            return null;
        }
        try {
            return Ed25519.publicKey(base64);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
