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
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.store.RosterEntryRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A record is verified against the roster as it was at acceptance time, and membership moves afterwards. The
 * auditor re-verifies every record when the roster changes and counts the ones whose signer is no longer
 * ACTIVE, which is the number the Phase 4 exit criteria require to be zero.
 *
 * <p>It measures and never repairs: an orphaned record keeps its bytes. Retraction is undefined in this
 * phase, and inventing one here would be a placement change nobody signed.
 */
@SpringBootTest(properties = {
        "gua.resolver.placement.enabled=true",
        "gua.resolver.placement.ingest-enabled=true"
})
@AutoConfigureMockMvc
@DirtiesContext
class PlacementRecordAuditorTest {

    private static final Ed25519.KeyPairB64 KEY = Ed25519.generate();

    @DynamicPropertySource
    static void ownDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () ->
                "jdbc:h2:mem:placement-audit;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
    }

    @Autowired MockMvc mockMvc;
    @Autowired AdmissionService admission;
    @Autowired RosterEntryRepository entries;
    @Autowired JdbcPlacementRecordStore store;
    @Autowired PlacementRecordAuditor auditor;

    @BeforeEach
    void admitTheHomeserver() {
        if (entries.findById("hs-aud").isEmpty()) {
            PlacementFixtures.admit(admission, "hs-aud", "aud.gua.test", KEY);
        }
    }

    @Test
    void aRecordWhoseSignerLeavesTheActiveRosterIsCountedAndKept() throws Exception {
        String accountId = PlacementFixtures.genesisAccountId("audit-one");
        byte[] canonical = PlacementFixtures.canonical(accountId, "hs-aud",
                Instant.now().truncatedTo(ChronoUnit.MILLIS));
        mockMvc.perform(post("/placement/records").contentType(MediaType.APPLICATION_JSON)
                        .content(PlacementFixtures.envelope(canonical, KEY)))
                .andExpect(status().isCreated());

        PlacementRecordAuditor.AuditResult clean = auditor.audit();
        assertThat(clean.records()).isEqualTo(1);
        assertThat(clean.orphanedByRoster()).isZero();
        assertThat(clean.invalidSignature()).isZero();

        admission.setStatus("hs-aud", RosterEntry.Status.SUSPENDED);

        // The roster moved, so the sweep runs on its own trigger rather than needing to be asked.
        auditor.auditIfRosterChanged();
        PlacementRecordAuditor.AuditResult after = auditor.audit();
        assertThat(after.records()).isEqualTo(1);
        assertThat(after.orphanedByRoster()).isEqualTo(1);

        // Custody: the bytes that arrived are the bytes that stay.
        assertThat(store.find(accountId).orElseThrow().recordB64())
                .isEqualTo(PlacementFixtures.recordB64(canonical));
    }
}
