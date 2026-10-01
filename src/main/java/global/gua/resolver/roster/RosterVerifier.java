package global.gua.resolver.roster;

import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

@Component
public class RosterVerifier {

    private final int threshold;
    private final Map<String, PublicKey> trustedKeys = new HashMap<>();
    private final MemberEntryVerifier memberVerifier;
    private final boolean requireMemberSignature;

    public RosterVerifier(ResolverProperties props) {
        this.threshold = Math.max(1, props.getAuthority().getThreshold());
        for (ResolverProperties.TrustedKey k : props.getAuthority().getTrustedKeys()) {
            if (k.getId() != null && k.getPublicKey() != null && !k.getPublicKey().isBlank()) {
                trustedKeys.put(k.getId(), Ed25519.publicKey(k.getPublicKey()));
            }
        }
        this.memberVerifier = new MemberEntryVerifier(props.getRoster().getMemberMaxLifetime());
        this.requireMemberSignature = props.getRoster().isRequireMemberSignature();
    }

    public boolean isVerified(SignedRoster roster) {
        return countValidSignatures(roster) >= threshold;
    }

    public void requireVerified(SignedRoster roster) {
        int valid = countValidSignatures(roster);
        if (valid < threshold) {
            throw new RosterVerificationException(
                    "roster v" + roster.version() + " has " + valid
                            + " valid authority signatures, need " + threshold);
        }
    }

    private int countValidSignatures(SignedRoster roster) {
        byte[] canonical = CanonicalRoster.bytes(roster);
        Set<String> counted = new HashSet<>();   // one vote per authority key
        int valid = 0;
        for (SignedRoster.AuthoritySignature sig : roster.authoritySignatures()) {
            PublicKey key = trustedKeys.get(sig.authorityKeyId());
            if (key == null || counted.contains(sig.authorityKeyId())) {
                continue;
            }
            if (Ed25519.verify(key, canonical, sig.signatureB64())) {
                counted.add(sig.authorityKeyId());
                valid++;
            }
        }
        return valid;
    }

    public int threshold() {
        return threshold;
    }

    public MemberEntryVerifier memberVerifier() {
        return memberVerifier;
    }

    public boolean requireMemberSignature() {
        return requireMemberSignature;
    }

    public record MemberCheck(String homeserverId, boolean active, MemberEntryVerifier.Result result) {}

    public record VerifiedView(List<RosterEntry> entries, List<MemberCheck> checks,
                               Set<String> unattestedActiveIds, List<MemberCheck> excluded,
                               Instant nextWindowChange) {

        public long unattestedActiveCount() {
            return unattestedActiveIds.size();
        }
    }

    public VerifiedView verifiedView(SignedRoster roster) {
        return verifiedView(roster.entries(), Instant.now(), id -> null, Set.of());
    }

    public VerifiedView verifiedView(List<RosterEntry> entries, Instant at,
                                     Function<String, MemberEntryVerifier.Prior> priors,
                                     Set<String> malformed) {
        List<RosterEntry> kept = new ArrayList<>(entries.size());
        List<MemberCheck> checks = new ArrayList<>(entries.size());
        List<MemberCheck> excluded = new ArrayList<>();
        Set<String> unattested = new LinkedHashSet<>();
        Instant next = null;

        for (RosterEntry entry : entries) {
            String id = entry.homeserver().id();
            MemberEntryVerifier.Result result = malformed.contains(id)
                    ? new MemberEntryVerifier.Result(MemberEntryVerifier.Outcome.INVALID,
                            "member block does not parse strictly", null)
                    : memberVerifier.verify(entry, at, priors.apply(id));
            MemberCheck check = new MemberCheck(id, entry.isActive(), result);
            checks.add(check);
            next = earlier(next, windowChange(entry, at));

            if (entry.isActive() && !result.valid()) {
                unattested.add(id);
                if (requireMemberSignature) {
                    excluded.add(check);
                    continue;
                }
            }
            kept.add(entry);
        }
        return new VerifiedView(List.copyOf(kept), List.copyOf(checks), Set.copyOf(unattested),
                List.copyOf(excluded), next);
    }

    private static Instant windowChange(RosterEntry entry, Instant at) {
        MemberAttestation m = entry.member();
        if (m == null || m.notBefore() == null || m.notAfter() == null) {
            return null;
        }
        if (m.notBefore().isAfter(at)) {
            return m.notBefore();
        }
        return m.notAfter().isBefore(at) ? null : m.notAfter().plusMillis(1);
    }

    private static Instant earlier(Instant a, Instant b) {
        if (a == null) {
            return b;
        }
        return b == null || a.isBefore(b) ? a : b;
    }

    public static class RosterVerificationException extends RuntimeException {
        public RosterVerificationException(String message) {
            super(message);
        }
    }
}
