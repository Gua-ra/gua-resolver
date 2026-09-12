package global.gua.resolver.placement.record;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.api.ResolveController;
import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.directory.JdbcDirectoryStore;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.store.RosterEntryRepository;
import global.gua.resolver.service.DefaultResolutionService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Nothing is served from placement records in this phase. This is the explicit non-goal, and it is a test so
 * that wiring the table into the resolution path fails the build rather than passing review.
 *
 * <p>It is checked three ways. Structurally, the resolution path holds no reference to the placement-record
 * package. Behaviourally, {@code /resolve} answers byte for byte the same with records stored as without
 * them, for an account the directory places and for one it does not. And by configuration, there is no
 * serve-from-records flag to turn on: the feature has a custody flag and an ingest flag, and that is all.
 *
 * <p>The deepest reason it cannot be served is in the record itself: it carries no identifier, so there is
 * nothing in it {@code /resolve} could key a phone lookup on. Phase 5's binding record is what would change
 * that, and it is not in this scope.
 */
@SpringBootTest(properties = {
        "gua.resolver.placement.enabled=true",
        "gua.resolver.placement.ingest-enabled=true"
})
@AutoConfigureMockMvc
@DirtiesContext
class PlacementRecordsAreNotServedTest {

    private static final String PLACEMENT_RECORD_PACKAGE = "global.gua.resolver.placement.record";
    private static final Ed25519.KeyPairB64 KEY = Ed25519.generate();

    @DynamicPropertySource
    static void ownDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () ->
                "jdbc:h2:mem:placement-not-served;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
    }

    @Autowired MockMvc mockMvc;
    @Autowired AdmissionService admission;
    @Autowired RosterEntryRepository entries;
    @Autowired JdbcDirectoryStore directory;
    @Autowired JdbcTransparencyLog transparencyLog;

    @BeforeEach
    void admitAHomeserver() {
        if (entries.findById("hs-one").isEmpty()) {
            PlacementFixtures.admit(admission, "hs-one", "one.gua.test", KEY);
        }
    }

    @Test
    void theResolutionPathHoldsNoReferenceToThePlacementRecordPackage() {
        assertNoPlacementRecordDependency(DefaultResolutionService.class);
        assertNoPlacementRecordDependency(ResolveController.class);
        assertNoPlacementRecordDependency(JdbcDirectoryStore.class);
    }

    @Test
    void resolveIsByteIdenticalWithAndWithoutStoredRecords() throws Exception {
        String placedPhone = "+5511900000101";
        String newPhone = "+5511900000102";
        directory.putPhone(placedPhone, "dev");
        try {
            String placedBefore = resolve(placedPhone);
            String newBefore = resolve(newPhone);
            long logBefore = transparencyLog.head().size();

            // Records that say these accounts live on a homeserver the directory never mentions.
            for (String seed : new String[] {"not-served-a", "not-served-b"}) {
                mockMvc.perform(post("/placement/records")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(PlacementFixtures.envelope(PlacementFixtures.canonical(
                                        PlacementFixtures.genesisAccountId(seed), "hs-one", now()), KEY)))
                        .andExpect(status().isCreated());
            }

            assertThat(resolve(placedPhone)).isEqualTo(placedBefore);
            assertThat(resolve(newPhone)).isEqualTo(newBefore);
            // Unchanged down to the roster version the answer is made against, because no leaf was appended.
            assertThat(transparencyLog.head().size()).isEqualTo(logBefore);
        } finally {
            directory.removePhone(placedPhone);
        }
    }

    @Test
    void thereIsNoServeFromRecordsFlag() {
        assertThat(ResolverProperties.Placement.class.getDeclaredMethods())
                .extracting(Method::getName)
                .allSatisfy(name -> assertThat(name.toLowerCase(Locale.ROOT))
                        .as("a placement property that would serve routing from records")
                        .doesNotContain("serve"));
    }

    private String resolve(String phone) throws Exception {
        return mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"" + phone + "\",\"trace\":true}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private static void assertNoPlacementRecordDependency(Class<?> type) {
        for (Field field : type.getDeclaredFields()) {
            assertThat(field.getType().getName())
                    .as("%s holds a %s", type.getSimpleName(), field.getType().getSimpleName())
                    .doesNotStartWith(PLACEMENT_RECORD_PACKAGE);
        }
        for (Constructor<?> constructor : type.getDeclaredConstructors()) {
            for (Class<?> parameter : constructor.getParameterTypes()) {
                assertThat(parameter.getName())
                        .as("%s is constructed with a %s", type.getSimpleName(), parameter.getSimpleName())
                        .doesNotStartWith(PLACEMENT_RECORD_PACKAGE);
            }
        }
        for (Method method : type.getDeclaredMethods()) {
            assertThat(method.getReturnType().getName())
                    .as("%s returns a %s", type.getSimpleName(), method.getReturnType().getSimpleName())
                    .doesNotStartWith(PLACEMENT_RECORD_PACKAGE);
            for (Class<?> parameter : method.getParameterTypes()) {
                assertThat(parameter.getName())
                        .as("%s takes a %s", type.getSimpleName(), parameter.getSimpleName())
                        .doesNotStartWith(PLACEMENT_RECORD_PACKAGE);
            }
        }
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MILLIS);
    }
}
