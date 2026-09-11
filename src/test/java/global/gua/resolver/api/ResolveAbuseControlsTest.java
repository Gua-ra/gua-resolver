package global.gua.resolver.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import global.gua.resolver.abuse.ClientKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The interim abuse controls end to end through the servlet stack, with prod-style trace configuration and
 * a small per-client budget. Client addresses are RFC 5737 documentation addresses. Runs in its own context
 * (custom properties) and dirties it so the bucket state never leaks into the other MockMvc tests.
 */
@SpringBootTest(properties = {
        "gua.resolver.abuse.client-limit-for-period=3",
        "gua.resolver.abuse.client-burst=3",
        "gua.resolver.abuse.client-refresh-period=PT1H",
        "gua.resolver.abuse.trace-enabled=false"
})
@AutoConfigureMockMvc
@DirtiesContext
class ResolveAbuseControlsTest {

    private static final String PHONE = "+5511987654321";

    @Autowired
    private MockMvc mockMvc;

    private static MockHttpServletRequestBuilder resolve(String client, String body) {
        return post("/resolve").header(ClientKey.FORWARDED_FOR, client)
                .contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static String bodyFor(String phone) {
        return "{\"phone\":\"" + phone + "\"}";
    }

    @Test
    void resolveWorksUnderTheLimitAndTheLimitIsPerClientAndPerPath() throws Exception {
        String client = "203.0.113.10";
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(resolve(client, bodyFor(PHONE)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.exists").value(false))
                    .andExpect(jsonPath("$.registerAt.serverName").value("gua.local"));
        }

        MvcResult refused = mockMvc.perform(resolve(client, bodyFor(PHONE)))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.code").value("rate_limited"))
                .andExpect(jsonPath("$.exists").doesNotExist())
                .andExpect(jsonPath("$.homeserver").doesNotExist())
                .andExpect(jsonPath("$.registerAt").doesNotExist())
                .andReturn();
        assertThat(refused.getResponse().getContentAsString()).doesNotContain(PHONE);
        assertThat(Long.parseLong(refused.getResponse().getHeader("Retry-After"))).isGreaterThanOrEqualTo(1);

        // A refused request reveals nothing about any phone: the body is the same constant for a different one.
        MvcResult refusedOther = mockMvc.perform(resolve(client, bodyFor("+14155550100")))
                .andExpect(status().isTooManyRequests()).andReturn();
        assertThat(refusedOther.getResponse().getContentAsString())
                .isEqualTo(refused.getResponse().getContentAsString());

        // Another client still gets served: the bucket is per client, not per pod.
        mockMvc.perform(resolve("203.0.113.11", bodyFor(PHONE)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false));

        // The filter is registered for /resolve only: the exhausted client can still read the roster.
        mockMvc.perform(get("/roster").header(ClientKey.FORWARDED_FOR, client))
                .andExpect(status().isOk());
    }

    @Test
    void traceIsWithheldWhenNotEnabledWithoutChangingTheContract() throws Exception {
        mockMvc.perform(resolve("203.0.113.20", "{\"phone\":\"" + PHONE + "\",\"trace\":true}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false))
                .andExpect(jsonPath("$.registerAt.serverName").value("gua.local"))
                .andExpect(jsonPath("$.trace").doesNotExist());
    }

    @Test
    void malformedRequestsNeverRevealExistence() throws Exception {
        String client = "203.0.113.30";
        for (String body : new String[] { "{\"phone\":", "{\"phone\":\"\"}", "{\"phone\":\"12345\"}", "[]" }) {
            MvcResult result = mockMvc.perform(resolve(client, body))
                    .andExpect(status().is4xxClientError())
                    .andReturn();
            assertThat(result.getResponse().getContentAsString())
                    .as("body for %s", body)
                    .doesNotContain("exists")
                    .doesNotContain("homeserver")
                    .doesNotContain("registerAt");
        }
    }
}
