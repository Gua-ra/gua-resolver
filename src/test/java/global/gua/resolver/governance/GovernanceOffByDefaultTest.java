package global.gua.resolver.governance;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import global.gua.resolver.admission.AdmissionRequest;
import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.store.RosterEntryRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Everything Phase 2 adds is off unless it is configured. With no genesis, the resolver behaves exactly as it
 * did before: an admission is ACTIVE immediately, a status change takes effect immediately, and the
 * well-known endpoint says there is nothing to serve rather than serving something misleading.
 *
 * <p>This is the deployed default in both environments, so it is worth a test of its own: the cutover is a
 * flag flip, and the flag being off has to mean the old behaviour exactly.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext
class GovernanceOffByDefaultTest {

    @DynamicPropertySource
    static void ownDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",
                () -> "jdbc:h2:mem:gov-off;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
    }

    @Autowired MockMvc mockMvc;
    @Autowired AdmissionService admission;
    @Autowired RosterEntryRepository entries;
    @Autowired GenesisLoader genesis;

    @Test
    void noGenesisMeansGovernanceIsOff() {
        assertThat(genesis.configured()).isFalse();
        assertThat(genesis.governanceRequired()).isFalse();
    }

    @Test
    void theWellKnownEndpointIsReachableAndReportsThereIsNoGenesis() throws Exception {
        mockMvc.perform(get("/.well-known/gua-federation")).andExpect(status().isNotFound());
    }

    @Test
    void anAdmissionIsActiveImmediatelyAndAStatusChangeTakesEffect() {
        String serverName = "ungoverned.gua.global";
        Ed25519.KeyPairB64 key = Ed25519.generate();
        String proof = Ed25519.sign(Ed25519.privateKey(key.privateKeyB64()),
                serverName.getBytes(StandardCharsets.UTF_8));

        admission.admit(new AdmissionRequest("ungoverned", serverName, "https://" + serverName,
                "https://account." + serverName, "BR", 1, true, key.publicKeyB64(), proof,
                "dns-txt-proof-token", List.of(), null, null));

        assertThat(entries.findById("ungoverned").orElseThrow().status())
                .isEqualTo(RosterEntry.Status.ACTIVE);

        admission.setStatus("ungoverned", RosterEntry.Status.SUSPENDED);

        assertThat(entries.findById("ungoverned").orElseThrow().status())
                .isEqualTo(RosterEntry.Status.SUSPENDED);
    }
}
