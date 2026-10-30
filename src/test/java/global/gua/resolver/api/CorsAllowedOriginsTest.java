package global.gua.resolver.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext
@TestPropertySource(properties = {
        "gua.resolver.cors.allowed-origins=https://chat.example.test,https://chat2.example.test",
        "spring.datasource.url=jdbc:h2:mem:cors-allowed;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
})
class CorsAllowedOriginsTest {

    private static final String ORIGIN = "https://chat.example.test";

    @Autowired MockMvc mockMvc;

    @Test
    void preflightForResolveFromAnAllowedOriginSucceeds() throws Exception {
        mockMvc.perform(options("/resolve")
                        .header("Origin", ORIGIN)
                        .header("Access-Control-Request-Method", "POST")
                        .header("Access-Control-Request-Headers", "content-type"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ORIGIN))
                .andExpect(header().string("Access-Control-Allow-Methods", "POST"));
    }

    @Test
    void rosterReadFromAnAllowedOriginCarriesTheHeader() throws Exception {
        mockMvc.perform(get("/roster").header("Origin", "https://chat2.example.test"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "https://chat2.example.test"));
    }

    @Test
    void anotherOriginIsRefused() throws Exception {
        mockMvc.perform(options("/resolve")
                        .header("Origin", "https://evil.example.test")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminEndpointsAreNotExposedCrossOrigin() throws Exception {
        mockMvc.perform(options("/authority/roster")
                        .header("Origin", ORIGIN)
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isForbidden());
    }
}
