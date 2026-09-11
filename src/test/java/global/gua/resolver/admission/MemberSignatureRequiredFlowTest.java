package global.gua.resolver.admission;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.CanonicalMemberEntry;
import global.gua.resolver.roster.MemberAttestation;
import global.gua.resolver.roster.MemberEntrySigner;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.RosterVerifier;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The transition flag as a cutover (ADM-007). With
 * {@code gua.resolver.roster.require-member-signature=true} an ACTIVE entry that carries no valid member
 * self-signature leaves the signed roster, placement and existing-account resolution, and the legacy
 * admission path is refused. Attesting the entry puts it back, which is why the deploy order is attest first,
 * flip second.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext
@TestPropertySource(properties = {
        "gua.resolver.roster.require-member-signature=true",
        "spring.datasource.url=jdbc:h2:mem:require-member;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
})
class MemberSignatureRequiredFlowTest {

    private static final Ed25519.KeyPairB64 DEV_KEY = Ed25519.generate();

    @DynamicPropertySource
    static void seededDevHomeserver(DynamicPropertyRegistry registry) {
        registry.add("gua.resolver.dev-homeserver.signing-key", DEV_KEY::publicKeyB64);
    }

    @Autowired RosterStore rosterStore;
    @Autowired RosterVerifier verifier;
    @Autowired AdmissionService admission;
    @Autowired MockMvc mockMvc;

    private static MemberAttestationRequest devAttestation() {
        Homeserver dev = new Homeserver("dev", "gua.local", "https://matrix.gua.local",
                "https://account.gua.local", "dev", 1, true, DEV_KEY.publicKeyB64(),
                Homeserver.SearchVisibility.GLOBAL, List.of());
        Instant notBefore = Instant.parse("2026-01-01T00:00:00Z");
        MemberAttestation member = MemberEntrySigner.sign(dev,
                new MemberAttestation(CanonicalMemberEntry.SCHEMA, CanonicalMemberEntry.ALG, "dev-1", 1,
                        notBefore, notBefore.plus(Duration.ofDays(400)), List.of()),
                "dev-1", DEV_KEY.privateKeyB64());
        return new MemberAttestationRequest(new MemberAttestationRequest.HomeserverFields(dev.id(),
                dev.serverName(), dev.baseUrl(), dev.masIssuer(), dev.signingKey(), dev.region(),
                dev.searchVisibility(), dev.searchGroups()), member);
    }

    @Test
    void anUnattestedActiveEntryIsExcludedUntilItIsAttested() throws Exception {
        // Seeded, unattested: it is counted, excluded from the signed roster, and cannot be routed to.
        assertThat(rosterStore.unattestedActiveCount()).isEqualTo(1);
        assertThat(rosterStore.current().entries()).isEmpty();
        SignedRoster excludedView = rosterStore.current();
        assertThat(verifier.isVerified(excludedView)).isTrue();   // signed over exactly what it serves
        mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"+5511987654321\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("no_placement_available"));

        admission.attest("dev", devAttestation());

        assertThat(rosterStore.unattestedActiveCount()).isZero();
        assertThat(rosterStore.current().entries()).hasSize(1);
        mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"+5511987654321\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.registerAt.serverName").value("gua.local"));
    }

    @Test
    void legacyAdmissionIsRefusedWhileTheFlagIsOn() {
        String serverName = "legacy-under-flag.gua.global";
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        String proof = Ed25519.sign(Ed25519.privateKey(kp.privateKeyB64()),
                serverName.getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> admission.admit(new AdmissionRequest(null, serverName,
                "https://" + serverName, "https://account." + serverName, "BR", 1, true,
                kp.publicKeyB64(), proof, "dns-txt-proof-token", List.of(), null, null)))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("member self-signature is required");
    }
}
