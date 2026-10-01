package global.gua.resolver.roster;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;

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

    public SignedRoster sign(long version, Instant issuedAt, List<RosterEntry> entries,
                             SignedRoster.LogCheckpoint checkpoint) {
        byte[] canonical = CanonicalRoster.bytes(version, issuedAt.toEpochMilli(), checkpoint, entries);
        List<SignedRoster.AuthoritySignature> sigs = signatureFor(canonical);
        return new SignedRoster(version, issuedAt, entries, checkpoint, sigs);
    }

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
            // No signing key configured: the roster is unsigned, and RosterVerifier rejects it.
            return List.of();
        }
        return List.of(new SignedRoster.AuthoritySignature(keyId, Ed25519.sign(signingKey, canonical)));
    }
}
