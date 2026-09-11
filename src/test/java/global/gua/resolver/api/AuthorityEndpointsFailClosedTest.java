package global.gua.resolver.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * With no admin password hash configured there are no admin users at all, so every {@code /authority/**}
 * route stays denied, including the member attestation route. This is the deployment default: an authority
 * surface that is reachable but unusable, rather than open.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthorityEndpointsFailClosedTest {

    @Autowired MockMvc mockMvc;

    @Test
    void memberAttestationIsDeniedWithAndWithoutCredentials() throws Exception {
        mockMvc.perform(post("/authority/roster/dev/member").contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/authority/roster/dev/member").contentType(MediaType.APPLICATION_JSON)
                        .with(httpBasic("admin", "anything")).content("{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void admissionIsDeniedWithAndWithoutCredentials() throws Exception {
        mockMvc.perform(post("/authority/admission").contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/authority/admission").contentType(MediaType.APPLICATION_JSON)
                        .with(httpBasic("admin", "anything")).content("{}"))
                .andExpect(status().isUnauthorized());
    }
}
