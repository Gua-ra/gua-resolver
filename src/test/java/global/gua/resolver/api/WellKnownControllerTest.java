package global.gua.resolver.api;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import global.gua.resolver.governance.CanonicalGenesis;
import global.gua.resolver.governance.FederationGenesis;
import global.gua.resolver.governance.GovernanceFixtures;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The genesis has to be fetchable by anyone, cacheable, and identified by its own hash, because the whole
 * point of publishing it is that someone can compare it against a channel the resolver does not control.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext
class WellKnownControllerTest {

    private static final GovernanceFixtures.Holder GOVERNANCE =
            GovernanceFixtures.Holder.of("gov-1", "operator-a");
    private static final FederationGenesis GENESIS =
            GovernanceFixtures.singleOperator("gua-wellknown-test", GOVERNANCE);
    private static final String GENESIS_ID = CanonicalGenesis.id(GENESIS);

    @DynamicPropertySource
    static void genesis(DynamicPropertyRegistry registry) throws Exception {
        Path file = Files.createTempDirectory("gua-wellknown").resolve("genesis.json");
        Files.writeString(file, GovernanceFixtures.mapper().writeValueAsString(GENESIS));
        registry.add("spring.datasource.url",
                () -> "jdbc:h2:mem:wellknown;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
        registry.add("gua.resolver.genesis.file", file::toString);
        registry.add("gua.resolver.genesis.expected-id", () -> GENESIS_ID);
    }

    @Autowired MockMvc mockMvc;

    @Test
    void theGenesisIsPublicCacheableAndTaggedWithItsOwnId() throws Exception {
        mockMvc.perform(get("/.well-known/gua-federation"))
                .andExpect(status().isOk())
                .andExpect(header().string("ETag", "\"" + GENESIS_ID + "\""))
                .andExpect(header().string("Cache-Control", "max-age=86400, public"))
                .andExpect(jsonPath("$.genesisId").value(GENESIS_ID))
                .andExpect(jsonPath("$.fingerprint").value(CanonicalGenesis.fingerprint(GENESIS_ID)))
                .andExpect(jsonPath("$.genesis.schema").value(FederationGenesis.SCHEMA))
                .andExpect(jsonPath("$.genesis.keys[0].operatorId").value("operator-a"))
                .andExpect(jsonPath("$.genesis.registries[0]").value("HomeserverRegistry"))
                .andExpect(jsonPath("$.transitions").isEmpty());
    }

    @Test
    void theServedDocumentCarriesNoPrivateKeyMaterial() throws Exception {
        String body = mockMvc.perform(get("/.well-known/gua-federation"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        org.assertj.core.api.Assertions.assertThat(body)
                .doesNotContain(GOVERNANCE.privateKeyB64())
                .contains(GOVERNANCE.key().publicKey());
    }

    @Test
    void theRegistryEndpointIsPublicAndSaysSoWhenNoEpochExists() throws Exception {
        // Public, not denied: a 404 here means "no epoch yet", not "authenticate first".
        mockMvc.perform(get("/registry/homeservers/epoch/current"))
                .andExpect(status().isNotFound());
    }

    @Test
    void theAdminEpochSurfaceStaysDenied() throws Exception {
        mockMvc.perform(get("/authority/registry/homeservers/pending"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void theDocumentSaysHowFarTheGovernanceKeyChainHasRun() throws Exception {
        // With no transition applied the head is the genesis id. It is published so an operator can pin it
        // and a reader can tell a full chain from a shortened one.
        mockMvc.perform(get("/.well-known/gua-federation"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.chainHead").value(GENESIS_ID))
                .andExpect(jsonPath("$.transitions").isEmpty());
    }

    @Test
    void theGenesisIsServedAsJson() throws Exception {
        mockMvc.perform(get("/.well-known/gua-federation"))
                .andExpect(content().contentTypeCompatibleWith("application/json"));
    }
}
