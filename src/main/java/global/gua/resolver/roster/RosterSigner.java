package global.gua.resolver.roster;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

/**
 * Authority-mode roster signer (§5). Assembles a {@link SignedRoster} from the current entries + log
 * checkpoint and attaches this authority's detached Ed25519 signature over the canonical bytes. With a
 * threshold &gt; 1, additional authorities sign the same canonical bytes and their signatures are merged
 * (see {@link #attach}); the roster is trusted once k distinct valid signatures are present.
 */
@Component
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class RosterSigner {

    private final String keyId;
    private final PrivateKey signingKey;

    public RosterSigner(ResolverProperties props) {
        ResolverProperties.Authority auth = props.getAuthority();
        this.keyId = auth.getSigningKeyId();
        this.signingKey = (auth.getSigningPrivateKey() == null || auth.getSigningPrivateKey().isBlank())
                ? null
                : Ed25519.privateKey(auth.getSigningPrivateKey());
    }

    /** Build a roster snapshot and sign it with this authority's key. */
    public SignedRoster sign(long version, Instant issuedAt, List<RosterEntry> entries,
                             SignedRoster.LogCheckpoint checkpoint) {
        byte[] canonical = CanonicalRoster.bytes(version, issuedAt.toEpochMilli(), checkpoint, entries);
        List<SignedRoster.AuthoritySignature> sigs = signatureFor(canonical);
        return new SignedRoster(version, issuedAt, entries, checkpoint, sigs);
    }

    /** Co-sign an existing roster (k-of-n): re-sign its canonical bytes and merge this authority's sig. */
    public SignedRoster attach(SignedRoster roster) {
        byte[] canonical = CanonicalRoster.bytes(roster);
        List<SignedRoster.AuthoritySignature> merged = new java.util.ArrayList<>(roster.authoritySignatures());
        for (SignedRoster.AuthoritySignature s : signatureFor(canonical)) {
            merged.removeIf(existing -> existing.authorityKeyId().equals(s.authorityKeyId()));
            merged.add(s);
        }
        return new SignedRoster(roster.version(), roster.issuedAt(), roster.entries(),
                roster.logCheckpoint(), merged);
    }

    public boolean canSign() {
        return signingKey != null && keyId != null;
    }

    private List<SignedRoster.AuthoritySignature> signatureFor(byte[] canonical) {
        if (!canSign()) {
            // Unsigned roster (no authority key configured yet). RosterVerifier will reject it unless the
            // threshold is met by other means — surfaced loudly rather than silently trusted.
            return List.of();
        }
        return List.of(new SignedRoster.AuthoritySignature(keyId, Ed25519.sign(signingKey, canonical)));
    }
}
