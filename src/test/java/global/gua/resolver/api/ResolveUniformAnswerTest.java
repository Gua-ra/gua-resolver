package global.gua.resolver.api;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import global.gua.resolver.admission.AdmissionRequest;
import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.directory.JdbcDirectoryStore;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.store.RosterEntryRepository;
import global.gua.resolver.service.ResolutionService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code POST /resolve} answers a number with an account and one without in the same shape, so the
 * response does not say whether an account exists, and a directory row on a homeserver that is not ACTIVE
 * fails closed instead of steering an existing account into registration elsewhere.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext
class ResolveUniformAnswerTest {

    private static final String HIT_DEV = "+5511900001001";
    private static final String HIT_HOME = "+5511900001002";
    private static final String MISS = "+5511900001003";
    private static final AtomicInteger CLIENTS = new AtomicInteger();

    @DynamicPropertySource
    static void ownDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () ->
                "jdbc:h2:mem:resolve-uniform;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
    }

    @Autowired MockMvc mockMvc;
    @Autowired AdmissionService admission;
    @Autowired RosterEntryRepository entries;
    @Autowired JdbcDirectoryStore directory;
    @Autowired ObjectMapper json;
    @MockitoSpyBean ResolutionService resolution;

    @BeforeEach
    void seed() {
        // Weight 0 and closed to new accounts: never a placement target, so a registerAt naming it can only
        // come from the directory.
        admitIfAbsent("home", "home.gua.test");
        directory.putPhone(HIT_DEV, "dev");
        directory.putPhone(HIT_HOME, "home");
        directory.removePhone(MISS);
        clearInvocations(resolution);
    }

    @Test
    void directoryHitAnswersWithTheAccountsHomeserverAsRegisterAt() throws Exception {
        resolve(HIT_HOME, false)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false))
                .andExpect(jsonPath("$.registerAt.serverName").value("home.gua.test"))
                .andExpect(jsonPath("$.registerAt.baseUrl").value("https://home.gua.test"))
                .andExpect(jsonPath("$.registerAt.masIssuer").value("https://account.home.gua.test"));
        JsonNode body = body(HIT_HOME);
        assertThat(body.has("homeserver")).isTrue();
        assertThat(body.get("homeserver").isNull()).isTrue();
    }

    @Test
    void directoryHitTraceNamesTheDirectory() throws Exception {
        resolve(HIT_HOME, true)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false))
                .andExpect(jsonPath("$.trace.source").value("directory"))
                .andExpect(jsonPath("$.trace.homeserverId").value("home"));
    }

    @Test
    void missAnswersWithThePlacementDecision() throws Exception {
        resolve(MISS, true)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false))
                .andExpect(jsonPath("$.registerAt.serverName").value("gua.local"))
                .andExpect(jsonPath("$.trace.source").value("placement"));
        assertThat(body(MISS).get("homeserver").isNull()).isTrue();
    }

    @Test
    void hitAndMissOnTheSameHomeserverAreByteIdentical() throws Exception {
        String hit = resolve(HIT_DEV, false).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString(StandardCharsets.UTF_8);
        String miss = resolve(MISS, false).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(hit).isEqualTo(miss);
    }

    @Test
    void hitAndMissCarryTheSameFields() throws Exception {
        JsonNode hit = body(HIT_HOME);
        JsonNode miss = body(MISS);

        assertThat(fieldNames(hit)).containsExactly("exists", "homeserver", "registerAt");
        assertThat(fieldNames(miss)).containsExactly("exists", "homeserver", "registerAt");
        assertThat(fieldNames(hit.get("registerAt"))).isEqualTo(fieldNames(miss.get("registerAt")));
    }

    @Test
    void placementRunsOnAHitAsOnAMiss() throws Exception {
        resolve(HIT_DEV, false).andExpect(status().isOk());
        verify(resolution, times(1)).placementDecisionFor(any());

        clearInvocations(resolution);
        resolve(MISS, false).andExpect(status().isOk());
        verify(resolution, times(1)).placementDecisionFor(any());
    }

    @Test
    void hitOnASuspendedHomeserverIsUnavailableAndNeverPlaced() throws Exception {
        assertUnavailableWithStatus("suspended", RosterEntry.Status.SUSPENDED, "+5511900001004");
    }

    @Test
    void hitOnARevokedHomeserverIsUnavailableAndNeverPlaced() throws Exception {
        assertUnavailableWithStatus("revoked", RosterEntry.Status.REVOKED, "+5511900001005");
    }

    @Test
    void hitOnAHomeserverMissingFromTheRosterIsUnavailableAndNeverPlaced() throws Exception {
        String phone = "+5511900001006";
        directory.putPhone(phone, "ghost");
        try {
            assertUnavailable(phone);
        } finally {
            directory.removePhone(phone);
        }
    }

    @Test
    void hitStillResolvesWhileNoHomeserverAcceptsNewAccounts() throws Exception {
        admission.setStatus("dev", RosterEntry.Status.SUSPENDED);
        try {
            resolve(MISS, false)
                    .andExpect(status().isServiceUnavailable())
                    .andExpect(jsonPath("$.code").value("no_placement_available"));
            resolve(HIT_HOME, false)
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.exists").value(false))
                    .andExpect(jsonPath("$.registerAt.serverName").value("home.gua.test"));
        } finally {
            admission.setStatus("dev", RosterEntry.Status.ACTIVE);
        }
    }

    private void assertUnavailableWithStatus(String id, RosterEntry.Status status, String phone) throws Exception {
        admitIfAbsent(id, id + ".gua.test");
        directory.putPhone(phone, id);
        admission.setStatus(id, status);
        try {
            assertUnavailable(phone);
        } finally {
            directory.removePhone(phone);
        }
    }

    private void assertUnavailable(String phone) throws Exception {
        String body = resolve(phone, true)
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("homeserver_unavailable"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(body).doesNotContain("registerAt").doesNotContain("exists").doesNotContain("trace");
        verify(resolution, times(0)).placementDecisionFor(any());
    }

    private void admitIfAbsent(String id, String serverName) {
        if (entries.findById(id).isPresent()) {
            return;
        }
        Ed25519.KeyPairB64 key = Ed25519.generate();
        String proof = Ed25519.sign(Ed25519.privateKey(key.privateKeyB64()),
                serverName.getBytes(StandardCharsets.UTF_8));
        admission.admit(new AdmissionRequest(id, serverName, "https://" + serverName,
                "https://account." + serverName, "BR", 0, false, key.publicKeyB64(), proof,
                "dns-txt-proof-token", List.of(), null, null));
    }

    private ResultActions resolve(String phone, boolean trace) throws Exception {
        String body = trace
                ? "{\"phone\":\"" + phone + "\",\"trace\":true}"
                : "{\"phone\":\"" + phone + "\"}";
        // A fresh client address per request keeps the per-client rate limit out of these assertions.
        String client = "192.0.2." + (CLIENTS.incrementAndGet() % 250 + 1);
        return mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON).content(body)
                .with(request -> {
                    request.setRemoteAddr(client);
                    return request;
                }));
    }

    private JsonNode body(String phone) throws Exception {
        return json.readTree(resolve(phone, false).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
