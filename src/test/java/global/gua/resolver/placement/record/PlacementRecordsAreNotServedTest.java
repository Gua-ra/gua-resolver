/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

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
import global.gua.resolver.placement.PlacementEngine;
import global.gua.resolver.placement.rules.WeightedFallbackRule;
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
 * <p>It is checked three ways. Structurally, no class that makes up the resolution path mentions the
 * placement-record package or the table's name anywhere in its bytecode. Behaviourally, {@code /resolve}
 * answers byte for byte the same with records stored as without them, for an account the directory places
 * and for one it does not. And by configuration, there is no serve-from-records flag to turn on: the feature
 * has a custody flag and an ingest flag, and that is all.
 *
 * <p>The structural check is deliberately not a list of class names. The resolution path is larger than any
 * list somebody remembers to update: {@code DefaultResolutionService} holds a {@link PlacementEngine} and
 * every {@link global.gua.resolver.placement.PlacementRule} behind it, so a rule added tomorrow is on the
 * path the day it is written. The class set is derived from the packages instead, and the check reads
 * compiled bytecode rather than the reflective surface, so a reference made inside a method body is caught
 * as well as a field, and the table name is checked as a string so that a raw JDBC query against
 * {@code placement_record} is caught even though it names no type.
 *
 * <p>The deepest reason it cannot be served is in the record itself: it carries no identifier, so there is
 * nothing in it {@code /resolve} could key a phone lookup on. Phase 5's binding record is what would change
 * that, and it is not in this scope.
 *
 * <p>One limit of the behavioural check, worth stating so the phrase "byte-identical" is not read as
 * unconditional: it holds while no checkpoint leaf has been published. A {@code PLACEMENT_CHECKPOINT} leaf
 * moves the log size, the log size is the roster version, and {@code WeightedFallbackRule} seeds on it
 * (ADM-001 L6 [CODE]), so once checkpoints publish, new-account placement does move as a function of
 * placement content. That is documented and accepted in ADM-008's consequences. What this test pins is the
 * rule that keeps it bounded: ingest itself appends no leaf, so the answer cannot move per record.
 */
@SpringBootTest(properties = {
        "gua.resolver.placement.enabled=true",
        "gua.resolver.placement.ingest-enabled=true"
})
@AutoConfigureMockMvc
@DirtiesContext
class PlacementRecordsAreNotServedTest {

    private static final String PLACEMENT_RECORD_PACKAGE = "global.gua.resolver.placement.record";

    /** The packages that together make up the resolution path. */
    private static final List<String> RESOLUTION_PATH_PACKAGES = List.of(
            "global.gua.resolver.service",
            "global.gua.resolver.placement",
            "global.gua.resolver.directory");

    /** The one class outside those packages that fronts the path. */
    private static final String RESOLUTION_CONTROLLER = ResolveController.class.getName();

    /** The record package as it is spelled in a constant pool. */
    private static final String RECORD_PACKAGE_MARKER = "global/gua/resolver/placement/record";

    /** The table, as it would be spelled by code that queried it without naming a type. */
    private static final String RECORD_TABLE_MARKER = "placement_record";

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
    void noClassOnTheResolutionPathMentionsPlacementRecordsAtAll() throws Exception {
        Map<String, byte[]> scanned = resolutionPathBytecode();

        // Derived from the packages, not listed. These are the load-bearing members of that set; if the scan
        // ever stops finding them it is the scan that broke, not the property that got safer.
        assertThat(scanned.keySet()).contains(
                DefaultResolutionService.class.getName(),
                PlacementEngine.class.getName(),
                WeightedFallbackRule.class.getName(),
                JdbcDirectoryStore.class.getName(),
                RESOLUTION_CONTROLLER);
        assertThat(scanned).hasSizeGreaterThanOrEqualTo(10);

        scanned.forEach((name, bytecode) -> {
            String constants = new String(bytecode, StandardCharsets.ISO_8859_1);
            assertThat(constants)
                    .as("%s refers to the placement-record package", name)
                    .doesNotContain(RECORD_PACKAGE_MARKER);
            assertThat(constants)
                    .as("%s names the placement_record table", name)
                    .doesNotContain(RECORD_TABLE_MARKER);
        });
    }

    @Test
    void theGuardDetectsAReferenceWhereThereIsOne() throws Exception {
        // A detector that can never fire would let the test above pass for the wrong reason. The store is the
        // known positive: it is typed on the record package and it names the table in its SQL.
        String store = new String(bytecodeOf(JdbcPlacementRecordStore.class), StandardCharsets.ISO_8859_1);

        assertThat(store).contains(RECORD_PACKAGE_MARKER);
        assertThat(store).contains(RECORD_TABLE_MARKER);
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

    /**
     * Every compiled class in the packages that make up the resolution path, plus the controller that fronts
     * it, keyed by class name. The record package is skipped: it is allowed to be itself.
     */
    private static Map<String, byte[]> resolutionPathBytecode() throws Exception {
        Path root = Path.of(DefaultResolutionService.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI());
        assertThat(Files.isDirectory(root))
                .as("compiled classes are readable as files under %s", root)
                .isTrue();
        Map<String, byte[]> found = new LinkedHashMap<>();
        try (Stream<Path> files = Files.walk(root)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".class")).toList()) {
                String relative = root.relativize(file).toString();
                String name = relative.substring(0, relative.length() - ".class".length())
                        .replace(File.separatorChar, '.');
                if (name.startsWith(PLACEMENT_RECORD_PACKAGE)) {
                    continue;
                }
                boolean inPath = RESOLUTION_PATH_PACKAGES.stream()
                        .anyMatch(pkg -> name.startsWith(pkg + "."));
                boolean isController = name.equals(RESOLUTION_CONTROLLER)
                        || name.startsWith(RESOLUTION_CONTROLLER + "$");
                if (inPath || isController) {
                    found.put(name, Files.readAllBytes(file));
                }
            }
        }
        return found;
    }

    private static byte[] bytecodeOf(Class<?> type) throws Exception {
        try (InputStream in = type.getClassLoader()
                .getResourceAsStream(type.getName().replace('.', '/') + ".class")) {
            assertThat(in).as("bytecode for %s", type.getName()).isNotNull();
            return in.readAllBytes();
        }
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MILLIS);
    }
}
