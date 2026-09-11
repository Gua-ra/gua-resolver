package global.gua.resolver.api;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.admission.MemberAttestationRequest;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.CanonicalMemberEntry;
import global.gua.resolver.roster.MemberAttestation;
import global.gua.resolver.roster.MemberEntrySigner;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The attest route over HTTP: it lives under {@code /authority/**}, so it needs the ADMIN role, and its body
 * is parsed strictly, so nothing outside the member's signature can ride along into the served roster.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext
class MemberAttestationControllerTest {

    private static final Ed25519.KeyPairB64 DEV_KEY = Ed25519.generate();
    private static final String ADMIN_PASSWORD = "member-attest-test-password";

    @DynamicPropertySource
    static void adminAndSeededKey(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",
                () -> "jdbc:h2:mem:attest-api;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
        registry.add("gua.resolver.dev-homeserver.signing-key", DEV_KEY::publicKeyB64);
        registry.add("gua.resolver.admin.password-hash",
                () -> new BCryptPasswordEncoder().encode(ADMIN_PASSWORD));
    }

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper json;

    private String attestationBody() throws Exception {
        Homeserver dev = new Homeserver("dev", "gua.local", "https://matrix.gua.local",
                "https://account.gua.local", "dev", 1, true, DEV_KEY.publicKeyB64(),
                Homeserver.SearchVisibility.GLOBAL, List.of());
        Instant notBefore = Instant.parse("2026-01-01T00:00:00Z");
        MemberAttestation member = MemberEntrySigner.sign(dev,
                new MemberAttestation(CanonicalMemberEntry.SCHEMA, CanonicalMemberEntry.ALG, "dev-1", 1,
                        notBefore, notBefore.plus(Duration.ofDays(400)), List.of()),
                "dev-1", DEV_KEY.privateKeyB64());
        return json.writeValueAsString(new MemberAttestationRequest(
                new MemberAttestationRequest.HomeserverFields(dev.id(), dev.serverName(), dev.baseUrl(),
                        dev.masIssuer(), dev.signingKey(), dev.region(), dev.searchVisibility(),
                        dev.searchGroups()),
                member));
    }

    @Test
    void theRouteRequiresTheAdminRole() throws Exception {
        mockMvc.perform(post("/authority/roster/dev/member").contentType(MediaType.APPLICATION_JSON)
                        .content(attestationBody()))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/authority/roster/dev/member").contentType(MediaType.APPLICATION_JSON)
                        .with(httpBasic("admin", "wrong-password"))
                        .content(attestationBody()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void anAcceptedAttestationAppearsInTheServedRoster() throws Exception {
        // Before: the seeded entry carries no member block at all, so the JSON is what clients see today.
        mockMvc.perform(get("/roster"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entries[0].member").doesNotExist());

        mockMvc.perform(post("/authority/roster/dev/member").contentType(MediaType.APPLICATION_JSON)
                        .with(httpBasic("admin", ADMIN_PASSWORD))
                        .content(attestationBody()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entries[0].member.keyId").value("dev-1"));

        mockMvc.perform(get("/roster"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entries[0].member.schema").value(CanonicalMemberEntry.SCHEMA))
                .andExpect(jsonPath("$.entries[0].member.sequence").value(1))
                .andExpect(jsonPath("$.entries[0].member.signatures[0].keyId").value("dev-1"));
    }

    @Test
    void anUnknownFieldInTheSignedSubObjectIsRefused() throws Exception {
        String tampered = attestationBody().replace("\"sequence\":1", "\"sequence\":1,\"weight\":100");

        mockMvc.perform(post("/authority/roster/dev/member").contentType(MediaType.APPLICATION_JSON)
                        .with(httpBasic("admin", ADMIN_PASSWORD))
                        .content(tampered))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("malformed_request"));
    }

    @Test
    void aDuplicateKeyAndInvalidUtf8AreRefused() throws Exception {
        String duplicated = attestationBody().replace("\"sequence\":1", "\"sequence\":1,\"sequence\":2");
        mockMvc.perform(post("/authority/roster/dev/member").contentType(MediaType.APPLICATION_JSON)
                        .with(httpBasic("admin", ADMIN_PASSWORD))
                        .content(duplicated))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("malformed_request"));

        mockMvc.perform(post("/authority/roster/dev/member").contentType(MediaType.APPLICATION_JSON)
                        .with(httpBasic("admin", ADMIN_PASSWORD))
                        .content(new byte[]{'{', (byte) 0xff, '}'}))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("malformed_request"));
    }

    @Test
    void anAttestationForAnUnknownHomeserverIsRejected() throws Exception {
        mockMvc.perform(post("/authority/roster/nosuch/member").contentType(MediaType.APPLICATION_JSON)
                        .with(httpBasic("admin", ADMIN_PASSWORD))
                        .content(attestationBody()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("admission_rejected"));
    }
}
