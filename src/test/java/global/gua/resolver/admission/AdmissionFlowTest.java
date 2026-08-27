package global.gua.resolver.admission;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;
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
                kp.publicKeyB64(), proof, "dns-txt-proof-token", claims, null, null);
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
                good.domainProof(), good.claims(), null, null);

        assertThatThrownBy(() -> admission.admit(forged))
                .isInstanceOf(AdmissionService.AdmissionException.class);
    }

    @Test
    void admissionDefaultsToGlobalSearchVisibility() {
        SignedRoster after = admission.admit(request("defaultvis.gua.global", List.of()));

        assertThat(after.entries()).anySatisfy(e -> {
            if (e.homeserver().serverName().equals("defaultvis.gua.global")) {
                assertThat(e.homeserver().searchVisibility())
                        .isEqualTo(Homeserver.SearchVisibility.GLOBAL);
                assertThat(e.homeserver().searchGroups()).isEmpty();
            }
        });
    }

    @Test
    void admissionCarriesGroupSearchVisibilityIntoTheSignedRoster() {
        AdmissionRequest base = request("grouped.gua.global", List.of());
        AdmissionRequest grouped = new AdmissionRequest(base.id(), base.serverName(), base.baseUrl(),
                base.masIssuer(), base.region(), base.weight(), base.acceptsNew(), base.signingKey(),
                base.keyPossessionProof(), base.domainProof(), base.claims(),
                "group", List.of("edu-br"));

        SignedRoster after = admission.admit(grouped);

        assertThat(after.entries()).anySatisfy(e -> {
            if (e.homeserver().serverName().equals("grouped.gua.global")) {
                assertThat(e.homeserver().searchVisibility())
                        .isEqualTo(Homeserver.SearchVisibility.GROUP);
                assertThat(e.homeserver().searchGroups()).containsExactly("edu-br");
            }
        });
        // the visibility policy is inside the signed bytes: roster still verifies
        assertThat(verifier.isVerified(after)).isTrue();
    }

    @Test
    void rejectsGroupVisibilityWithoutGroupsAndGroupsWithoutGroupVisibility() {
        AdmissionRequest base = request("badvis.gua.global", List.of());
        AdmissionRequest groupNoGroups = new AdmissionRequest(base.id(), base.serverName(),
                base.baseUrl(), base.masIssuer(), base.region(), base.weight(), base.acceptsNew(),
                base.signingKey(), base.keyPossessionProof(), base.domainProof(), base.claims(),
                "GROUP", List.of());
        assertThatThrownBy(() -> admission.admit(groupNoGroups))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("requires at least one search group");

        AdmissionRequest groupsNoGroup = new AdmissionRequest(base.id(), base.serverName(),
                base.baseUrl(), base.masIssuer(), base.region(), base.weight(), base.acceptsNew(),
                base.signingKey(), base.keyPossessionProof(), base.domainProof(), base.claims(),
                "server", List.of("edu-br"));
        assertThatThrownBy(() -> admission.admit(groupsNoGroup))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("only valid with searchVisibility GROUP");
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
