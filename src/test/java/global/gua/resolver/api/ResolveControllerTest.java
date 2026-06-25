package global.gua.resolver.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

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
                .andExpect(jsonPath("$.registerAt.masIssuer").value("https://account.gua.local"));
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
                .andExpect(jsonPath("$.version").value(1))
                .andExpect(jsonPath("$.entries[0].homeserver.serverName").value("gua.local"))
                .andExpect(jsonPath("$.entries[0].homeserver.acceptsNew").value(true))
                .andExpect(jsonPath("$.logCheckpoint.size").value(1))
                .andExpect(jsonPath("$.logCheckpoint.merkleRoot").isNotEmpty())
                .andExpect(jsonPath("$.authoritySignatures[0].authorityKeyId").value("gua-authority-test"));
    }
}
