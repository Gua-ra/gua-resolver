/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

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
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.store.RosterEntryRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * With custody on and ingest off, a record that would otherwise be accepted is refused, and the reads still
 * answer. The record presented is valid in every other respect, so a 503 can only be the flag.
 */
@SpringBootTest(properties = {
        "gua.resolver.placement.enabled=true",
        "gua.resolver.placement.ingest-enabled=false"
})
@AutoConfigureMockMvc
@DirtiesContext
class PlacementIngestFlagTest {

    private static final Ed25519.KeyPairB64 MEMBER = Ed25519.generate();

    @DynamicPropertySource
    static void ownDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () ->
                "jdbc:h2:mem:placement-ingest-flag;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
    }

    @Autowired MockMvc mockMvc;
    @Autowired AdmissionService admission;
    @Autowired RosterEntryRepository entries;
    @Autowired JdbcPlacementRecordStore store;

    @BeforeEach
    void admitAHomeserver() {
        if (entries.findById("hs-one").isEmpty()) {
            PlacementFixtures.admit(admission, "hs-one", "one.gua.test", MEMBER);
        }
    }

    @Test
    void anOtherwiseAcceptableRecordIsRefusedWhileTheIngestFlagIsOff() throws Exception {
        String accountId = PlacementFixtures.genesisAccountId("flag-off-valid");

        mockMvc.perform(post("/placement/records").contentType(MediaType.APPLICATION_JSON)
                        .content(PlacementFixtures.envelope(
                                PlacementFixtures.canonical(accountId, "hs-one", now()), MEMBER)))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("ingest_disabled"));

        assertThat(store.find(accountId)).isEmpty();
        assertThat(store.count()).isZero();
    }

    @Test
    void theReadsStillAnswerWhileTheIngestFlagIsOff() throws Exception {
        // Reads are unaffected by the ingest flag: the custody flag is what mounts them.
        mockMvc.perform(get("/placement/records/"
                        + PlacementFixtures.genesisAccountId("flag-off-absent")))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("no_placement_record"));

        mockMvc.perform(get("/placement/records").queryParam("homeserverId", "hs-one"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.homeserverId").value("hs-one"))
                .andExpect(jsonPath("$.records.length()").value(0));
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MILLIS);
    }
}
