package global.gua.resolver.admission;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.RosterVerifier;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * End-to-end admission against the real authority stack: admitting a homeserver vets its key-possession +
 * domain proof, appends an ADMIT event to the transparency log, and re-signs a roster that still verifies;
 * overlapping claims are rejected. Dirties the context so its writes don't leak into other @SpringBootTests.
 */
@SpringBootTest
@DirtiesContext
class AdmissionFlowTest {

    @Autowired RosterStore rosterStore;
    @Autowired RosterVerifier verifier;
    @Autowired AdmissionService admission;

    private AdmissionRequest request(String serverName, List<ClaimPredicate> claims) {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        String proof = Ed25519.sign(Ed25519.privateKey(kp.privateKeyB64()),
                serverName.getBytes(StandardCharsets.UTF_8));
        return new AdmissionRequest(null, serverName, "https://" + serverName,
                "https://account." + serverName, "BR", 1, true,
                kp.publicKeyB64(), proof, "dns-txt-proof-token", claims);
    }

    @Test
    void admittingGrowsTheLogAndKeepsTheRosterVerifiable() {
        long before = rosterStore.current().logCheckpoint().size();

        SignedRoster after = admission.admit(request("usp.gua.global",
                List.of(new ClaimPredicate(null, null, null, null, "usp.br", null, null, 100))));

        assertThat(after.logCheckpoint().size()).isEqualTo(before + 1);
        assertThat(after.entries()).anySatisfy(e ->
                assertThat(e.homeserver().serverName()).isEqualTo("usp.gua.global"));
        assertThat(verifier.isVerified(after)).isTrue();
    }

    @Test
    void rejectsKeyPossessionForgery() {
        AdmissionRequest good = request("forge.gua.global", List.of());
        AdmissionRequest forged = new AdmissionRequest(null, good.serverName(), good.baseUrl(),
                good.masIssuer(), good.region(), good.weight(), good.acceptsNew(),
                good.signingKey(), Ed25519.generate().publicKeyB64(),  // proof not made by signingKey
                good.domainProof(), good.claims());

        assertThatThrownBy(() -> admission.admit(forged))
                .isInstanceOf(AdmissionService.AdmissionException.class);
    }

    @Test
    void rejectsOverlappingClaims() {
        ClaimPredicate vivo = new ClaimPredicate(null, "72411", null, null, null, null, null, 100);
        admission.admit(request("vivo.gua.global", List.of(vivo)));

        // A second homeserver claiming the same MCCMNC must be refused.
        assertThatThrownBy(() ->
                admission.admit(request("vivo2.gua.global", List.of(
                        new ClaimPredicate(null, "72411", null, null, null, null, null, 100)))))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("overlap");
    }
}
