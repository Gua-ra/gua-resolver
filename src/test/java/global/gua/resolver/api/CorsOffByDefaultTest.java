package global.gua.resolver.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** With no allowed origin configured, a browser preflight is refused and reads carry no CORS header. */
@SpringBootTest
@AutoConfigureMockMvc
class CorsOffByDefaultTest {

    @Autowired MockMvc mockMvc;

    @Test
    void preflightIsRefused() throws Exception {
        mockMvc.perform(options("/resolve")
                        .header("Origin", "https://chat.example.test")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isForbidden());
    }

    @Test
    void readsCarryNoAllowOriginHeader() throws Exception {
        mockMvc.perform(get("/roster").header("Origin", "https://chat.example.test"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }
}
