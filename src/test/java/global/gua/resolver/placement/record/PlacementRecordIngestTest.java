/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.store.RosterEntryRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The ingest and custody rules end to end (migration plan Phase 4, ADM-008 decision 7): insert when the
 * accountId has no home, replace on a newer re-issue by the holder, refuse a claim from anyone else, and
 * serve the stored envelope back exactly as it arrived.
 *
 * <p>The last test is the one that keeps the design honest about the transparency log: accepting records
 * appends no leaf. The roster version is the log size and new-account fallback placement seeds on it, so a
 * leaf per record would move placement decisions on every ingest (ADM-001 L6).
 */
@SpringBootTest(properties = {
        "gua.resolver.placement.enabled=true",
        "gua.resolver.placement.ingest-enabled=true"
})
@AutoConfigureMockMvc
@DirtiesContext
class PlacementRecordIngestTest {

    private static final Ed25519.KeyPairB64 ONE = Ed25519.generate();
    private static final Ed25519.KeyPairB64 TWO = Ed25519.generate();

    @DynamicPropertySource
    static void ownDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () ->
                "jdbc:h2:mem:placement-ingest;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
    }

    @Autowired MockMvc mockMvc;
    @Autowired AdmissionService admission;
    @Autowired RosterEntryRepository entries;
    @Autowired JdbcPlacementRecordStore store;
    @Autowired JdbcTransparencyLog transparencyLog;
    @Autowired JdbcTemplate jdbc;

    @BeforeEach
    void admitTwoHomeservers() {
        if (entries.findById("hs-one").isEmpty()) {
            PlacementFixtures.admit(admission, "hs-one", "one.gua.test", ONE);
        }
        if (entries.findById("hs-two").isEmpty()) {
            PlacementFixtures.admit(admission, "hs-two", "two.gua.test", TWO);
        }
    }

    @Test
    void aRecordSignedByTheHoldingHomeserverIsStoredAndServedBackVerbatim() throws Exception {
        String accountId = PlacementFixtures.genesisAccountId("ingest-ok");
        byte[] canonical = PlacementFixtures.canonical(accountId, "hs-one", now());
        String recordB64 = PlacementFixtures.recordB64(canonical);
        String signature = PlacementFixtures.sign(canonical, ONE);

        present(PlacementFixtures.envelope(recordB64, signature))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.result").value("stored"));

        // Verbatim: the bytes that were signed are the bytes that are served, not a re-encoding of them.
        mockMvc.perform(get("/placement/records/" + accountId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.record").value(recordB64))
                .andExpect(jsonPath("$.signature").value(signature));

        StoredPlacementRecord held = store.find(accountId).orElseThrow();
        assertThat(held.homeserverId()).isEqualTo("hs-one");
        assertThat(held.origin()).isEqualTo(PlacementRecord.Origin.GENESIS);
        assertThat(held.generation()).isEqualTo(1);
    }

    @Test
    void aBootstrapRecordKeepsItsOriginThroughStorage() throws Exception {
        String accountId = PlacementFixtures.bootstrapAccountId("ingest-bootstrap");

        present(PlacementFixtures.envelope(
                PlacementFixtures.canonical(accountId, "hs-one", now()), ONE))
                .andExpect(status().isCreated());

        assertThat(store.find(accountId).orElseThrow().origin())
                .isEqualTo(PlacementRecord.Origin.BOOTSTRAP);
    }

    @Test
    void aReissueWithANewerIssuedAtReplacesTheStoredRecord() throws Exception {
        String accountId = PlacementFixtures.genesisAccountId("ingest-reissue");
        present(PlacementFixtures.envelope(
                PlacementFixtures.canonical(accountId, "hs-one", now().minus(Duration.ofHours(2))), ONE))
                .andExpect(status().isCreated());

        byte[] newer = PlacementFixtures.canonical(accountId, "hs-one", now().minus(Duration.ofHours(1)));
        present(PlacementFixtures.envelope(newer, ONE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("replaced"));

        assertThat(store.find(accountId).orElseThrow().recordB64())
                .isEqualTo(PlacementFixtures.recordB64(newer));
    }

    @Test
    void aReissueThatIsNotNewerIsRefusedAndTheHeldRecordStands() throws Exception {
        String accountId = PlacementFixtures.genesisAccountId("ingest-stale");
        byte[] held = PlacementFixtures.canonical(accountId, "hs-one", now().minus(Duration.ofHours(1)));
        present(PlacementFixtures.envelope(held, ONE)).andExpect(status().isCreated());

        present(PlacementFixtures.envelope(
                PlacementFixtures.canonical(accountId, "hs-one", now().minus(Duration.ofHours(3))), ONE))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("stale_reissue"));

        assertThat(store.find(accountId).orElseThrow().recordB64())
                .isEqualTo(PlacementFixtures.recordB64(held));
    }

    @Test
    void theSameBytesPresentedAgainChangeNothing() throws Exception {
        String accountId = PlacementFixtures.genesisAccountId("ingest-retry");
        String envelope = PlacementFixtures.envelope(
                PlacementFixtures.canonical(accountId, "hs-one", now()), ONE);

        present(envelope).andExpect(status().isCreated());
        present(envelope)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("unchanged"));
    }

    @Test
    void aRetryThatSpellsTheSignatureDifferentlyIsStillTheSameRecord() throws Exception {
        String accountId = PlacementFixtures.genesisAccountId("ingest-retry-spelling");
        byte[] canonical = PlacementFixtures.canonical(accountId, "hs-one", now());
        String recordB64 = PlacementFixtures.recordB64(canonical);
        String signature = PlacementFixtures.sign(canonical, ONE);
        // An Ed25519 signature is 64 bytes, so its base64 ends in padding that a decoder treats as optional.
        // Both spellings are one signature over one set of bytes.
        String unpadded = signature.replace("=", "");
        assertThat(unpadded).isNotEqualTo(signature);

        present(PlacementFixtures.envelope(recordB64, signature)).andExpect(status().isCreated());

        // A publisher retrying after a timeout must not be told its own record conflicts with itself. The
        // idempotence rule is about the object, so the comparison is on bytes, not on transport spelling.
        present(PlacementFixtures.envelope(recordB64, unpadded))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("unchanged"));

        // And the held copy is still the one that arrived first, byte for byte.
        assertThat(store.find(accountId).orElseThrow().signatureB64()).isEqualTo(signature);
    }

    @Test
    void theStoredRowCarriesNoIdentifierColumn() {
        List<String> columns = jdbc.queryForList(
                        "SELECT column_name FROM information_schema.columns "
                                + "WHERE UPPER(table_name) = 'PLACEMENT_RECORD'", String.class)
                .stream().map(c -> c.toLowerCase(Locale.ROOT)).sorted().toList();

        // The row is pinned, not only the decoded object: a phone, a phone hash or a Matrix user id added as
        // a column later would otherwise reach a deployment without failing anything (ADM-001 L4, L15).
        assertThat(columns).containsExactly("account_id", "generation", "homeserver_id", "issued_at",
                "not_after", "not_before", "origin", "received_at", "record_b64", "signature_b64");
    }

    @Test
    void aSecondHomeserverClaimingTheSameAccountIsRefusedWithAConflict() throws Exception {
        String accountId = PlacementFixtures.genesisAccountId("ingest-conflict");
        byte[] held = PlacementFixtures.canonical(accountId, "hs-one", now());
        present(PlacementFixtures.envelope(held, ONE)).andExpect(status().isCreated());

        // A validly signed record from another ACTIVE member: one accountId has one home, so this is a
        // conflict, never an overwrite and never a migration (ADM-001 L9).
        present(PlacementFixtures.envelope(
                PlacementFixtures.canonical(accountId, "hs-two", now()), TWO))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("placement_conflict"));

        StoredPlacementRecord after = store.find(accountId).orElseThrow();
        assertThat(after.homeserverId()).isEqualTo("hs-one");
        assertThat(after.recordB64()).isEqualTo(PlacementFixtures.recordB64(held));
    }

    @Test
    void theListingPagesByHomeserverAndRefusesToListWithoutOne() throws Exception {
        List<String> ids = List.of(
                PlacementFixtures.genesisAccountId("ingest-list-a"),
                PlacementFixtures.genesisAccountId("ingest-list-b"),
                PlacementFixtures.genesisAccountId("ingest-list-c")).stream().sorted().toList();
        for (String id : ids) {
            present(PlacementFixtures.envelope(PlacementFixtures.canonical(id, "hs-two", now()), TWO))
                    .andExpect(status().isCreated());
        }

        mockMvc.perform(get("/placement/records")
                        .queryParam("homeserverId", "hs-two").queryParam("limit", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(2))
                .andExpect(jsonPath("$.records[0].accountId").value(ids.get(0)))
                .andExpect(jsonPath("$.records[1].accountId").value(ids.get(1)))
                .andExpect(jsonPath("$.nextCursor").value(ids.get(1)));

        mockMvc.perform(get("/placement/records")
                        .queryParam("homeserverId", "hs-two")
                        .queryParam("cursor", ids.get(1)).queryParam("limit", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(1))
                .andExpect(jsonPath("$.records[0].accountId").value(ids.get(2)))
                .andExpect(jsonPath("$.nextCursor").doesNotExist());

        // There is no listing of everything this node holds.
        mockMvc.perform(get("/placement/records"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("homeserver_id_required"));
    }

    @Test
    void aReadForAnAccountWithNoRecordIsANotFoundAndAMalformedIdIsARefusal() throws Exception {
        mockMvc.perform(get("/placement/records/"
                        + PlacementFixtures.genesisAccountId("ingest-absent")))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("no_placement_record"));

        mockMvc.perform(get("/placement/records/ga1-not-an-account-id"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_account_id"));
    }

    @Test
    void acceptingRecordsAppendsNoTransparencyLogLeaf() throws Exception {
        long before = transparencyLog.head().size();

        for (String seed : List.of("ingest-leaf-a", "ingest-leaf-b", "ingest-leaf-c")) {
            present(PlacementFixtures.envelope(PlacementFixtures.canonical(
                    PlacementFixtures.genesisAccountId(seed), "hs-one", now()), ONE))
                    .andExpect(status().isCreated());
        }

        // The log is not reseeded per record; anchoring is the checkpoint's job, once per changed root.
        assertThat(transparencyLog.head().size()).isEqualTo(before);
    }

    private ResultActions present(String body) throws Exception {
        return mockMvc.perform(post("/placement/records")
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MILLIS);
    }
}
