package global.gua.resolver.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Contract test for the resolver front door, against the Phase-1 dev wiring (single homeserver from
 * config, empty directory). Locks the JSON shape the iOS/web ResolverClients decode.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ResolveControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void resolveNewPhoneReturnsRegisterTarget() throws Exception {
        // No account exists yet (empty directory) -> exists=false, register at the dev homeserver.
        mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"+5511987654321\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false))
                .andExpect(jsonPath("$.registerAt.serverName").value("gua.local"))
                .andExpect(jsonPath("$.registerAt.baseUrl").value("https://matrix.gua.local"))
                .andExpect(jsonPath("$.registerAt.masIssuer").value("https://account.gua.local"))
                .andExpect(jsonPath("$.trace").doesNotExist());
    }

    @Test
    void resolveCanReturnDecisionTraceWhenRequested() throws Exception {
        mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"+5511987654321\",\"trace\":true}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false))
                .andExpect(jsonPath("$.trace.source").value("placement"))
                .andExpect(jsonPath("$.trace.rule").value("WeightedFallbackRule"))
                .andExpect(jsonPath("$.trace.homeserverId").value("dev"));
    }

    @Test
    void resolveRejectsNonE164PhoneWith400() throws Exception {
        // A partial / non-E.164 number is a client error: expect a clean 400, not a 500.
        for (String bad : new String[] { "+1", "notaphone", "12345" }) {
            mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                            .content("{\"phone\":\"" + bad + "\"}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("invalid_phone"));
        }
    }

    @Test
    void resolveRejectsBlankPhoneWith400() throws Exception {
        mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rosterReturnsSignedRosterWithDevHomeserver() throws Exception {
        mockMvc.perform(get("/roster"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(greaterThanOrEqualTo(1)))
                .andExpect(jsonPath("$.entries[0].homeserver.serverName").value("gua.local"))
                .andExpect(jsonPath("$.entries[0].homeserver.acceptsNew").value(true))
                .andExpect(jsonPath("$.logCheckpoint.size").value(greaterThanOrEqualTo(1)))
                .andExpect(jsonPath("$.logCheckpoint.merkleRoot").isNotEmpty())
                .andExpect(jsonPath("$.authoritySignatures[0].authorityKeyId").value("gua-authority-test"));
    }

    @Test
    void unknownRoutesAreDeniedByDefault() throws Exception {
        // deny-by-default + HTTP Basic entry point: an anonymous hit on a non-allowlisted route is challenged.
        mockMvc.perform(get("/not-a-real-endpoint"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void authorityAdminEndpointsAreDeniedWithoutAdminCredentials() throws Exception {
        // No admin password hash is configured in tests, so /authority/** must not be reachable anonymously.
        mockMvc.perform(post("/authority/admission").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void selfAssertedVerifiedMarkerAndAffiliationsDoNotChangePlacement() throws Exception {
        // Regression for the self-assertion bypass: a public caller cannot fake verified institution claims.
        // With only the dev homeserver and no signed envelope, this must still be a plain fallback register,
        // never an institutional placement, and never a 500.
        mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"+5511987654321\",\"trace\":true,"
                                + "\"affiliations\":[\"usp.br\"],"
                                + "\"attributes\":{\"gua_claims_verified\":\"true\",\"email_domain\":\"usp.br\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false))
                .andExpect(jsonPath("$.registerAt.serverName").value("gua.local"))
                .andExpect(jsonPath("$.trace.rule").value("WeightedFallbackRule"));
    }

    @Test
    void nullAttributeValuesAreHandledGracefully() throws Exception {
        // A null attribute value must not blow up the request thread (previously a 500 via Map.copyOf).
        mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"+5511987654321\",\"attributes\":{\"x\":null}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false));
    }

    @Test
    void policyStatusEndpointExistsWhenNoPolicySourceIsConfigured() throws Exception {
        mockMvc.perform(get("/policy/routing/status"))
                .andExpect(status().isOk());
    }
}
