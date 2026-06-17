package global.gua.resolver.roster;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Authority-signature trust gate (§5): a roster signed by a trusted key verifies; tampering with an entry
 * invalidates it; and a k-of-n threshold is enforced (one signature does not satisfy a 2-of-n policy).
 */
class RosterSignatureTest {

    private static RosterEntry entry(String id) {
        Homeserver hs = new Homeserver(id, id + ".gua.global", "https://" + id, "https://" + id + "/auth",
                "BR", 1, true, "");
        return new RosterEntry(hs, List.of(), Instant.now(), RosterEntry.Status.ACTIVE);
    }

    private static ResolverProperties props(int threshold, String keyId, String priv,
                                            List<ResolverProperties.TrustedKey> trusted) {
        ResolverProperties p = new ResolverProperties();
        p.getAuthority().setThreshold(threshold);
        p.getAuthority().setSigningKeyId(keyId);
        p.getAuthority().setSigningPrivateKey(priv);
        p.getAuthority().setTrustedKeys(trusted);
        return p;
    }

    private static ResolverProperties.TrustedKey trusted(String id, String pub) {
        ResolverProperties.TrustedKey k = new ResolverProperties.TrustedKey();
        k.setId(id);
        k.setPublicKey(pub);
        return k;
    }

    @Test
    void signedRosterVerifiesAndTamperingBreaksIt() {
        Ed25519.KeyPairB64 a = Ed25519.generate();
        ResolverProperties props = props(1, "auth-a", a.privateKeyB64(),
                List.of(trusted("auth-a", a.publicKeyB64())));
        RosterSigner signer = new RosterSigner(props);
        RosterVerifier verifier = new RosterVerifier(props);

        SignedRoster signed = signer.sign(1, Instant.now(), List.of(entry("h1")),
                new SignedRoster.LogCheckpoint("root", 1));
        assertThat(verifier.isVerified(signed)).isTrue();

        // Swap in a different entry under the same signatures -> canonical bytes change -> verification fails.
        SignedRoster tampered = new SignedRoster(signed.version(), signed.issuedAt(),
                List.of(entry("evil")), signed.logCheckpoint(), signed.authoritySignatures());
        assertThat(verifier.isVerified(tampered)).isFalse();
    }

    @Test
    void thresholdRequiresKOfN() {
        Ed25519.KeyPairB64 a = Ed25519.generate();
        Ed25519.KeyPairB64 b = Ed25519.generate();
        // Policy: 2-of-2. Only authority A signs.
        ResolverProperties props = props(2, "auth-a", a.privateKeyB64(),
                List.of(trusted("auth-a", a.publicKeyB64()), trusted("auth-b", b.publicKeyB64())));
        RosterSigner signerA = new RosterSigner(props);
        RosterVerifier verifier = new RosterVerifier(props);

        SignedRoster oneSig = signerA.sign(1, Instant.now(), List.of(entry("h1")),
                new SignedRoster.LogCheckpoint("root", 1));
        assertThat(oneSig.authoritySignatures()).hasSize(1);
        assertThat(verifier.isVerified(oneSig)).as("1 of 2 is below threshold").isFalse();

        // Authority B co-signs -> now 2 of 2.
        ResolverProperties propsB = props(2, "auth-b", b.privateKeyB64(),
                List.of(trusted("auth-a", a.publicKeyB64()), trusted("auth-b", b.publicKeyB64())));
        SignedRoster twoSig = new RosterSigner(propsB).attach(oneSig);
        assertThat(twoSig.authoritySignatures()).hasSize(2);
        assertThat(verifier.isVerified(twoSig)).as("2 of 2 meets threshold").isTrue();
    }
}
