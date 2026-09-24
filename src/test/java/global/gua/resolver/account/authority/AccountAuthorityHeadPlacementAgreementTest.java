/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

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
import global.gua.resolver.placement.record.AccountId;
import global.gua.resolver.placement.record.PlacementRecord;
import global.gua.resolver.placement.record.PlacementRecordCodec;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.TransparencyLog;
import global.gua.resolver.roster.store.RosterEntryRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Entitlement, where the resolver has evidence that did not come from the publisher.
 *
 * <p>Roster membership says a homeserver may publish heads. It does not say for which accounts, and the resolver
 * holds no account list of its own, so first-claim-wins is otherwise the whole rule. Where placement custody is
 * also on, the resolver does hold one independent statement about where an account lives, and a head that
 * contradicts it is refused rather than stored beside it.
 *
 * <p>Both flag pairs are on here, which is the only combination where that check runs. With placement off the
 * store bean does not exist and the head service compares against nothing, which is asserted by the other
 * publication tests: they all run with placement off and heads are accepted there on roster membership alone.
 */
@SpringBootTest(properties = {
        "gua.resolver.account-authority.enabled=true",
        "gua.resolver.account-authority.ingest-enabled=true",
        "gua.resolver.placement.enabled=true",
        "gua.resolver.placement.ingest-enabled=true"
})
@AutoConfigureMockMvc
@DirtiesContext
class AccountAuthorityHeadPlacementAgreementTest {

    private static final Ed25519.KeyPairB64 ONE = Ed25519.generate();
    private static final Ed25519.KeyPairB64 TWO = Ed25519.generate();

    @DynamicPropertySource
    static void ownDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () ->
                "jdbc:h2:mem:authority-head-placement;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;"
                        + "DB_CLOSE_ON_EXIT=FALSE");
    }

    @Autowired MockMvc mockMvc;
    @Autowired AdmissionService admission;
    @Autowired RosterEntryRepository entries;
    @Autowired JdbcAccountAuthorityHeadStore store;
    @Autowired JdbcTransparencyLog transparencyLog;

    @BeforeEach
    void admitTwoHomeservers() {
        if (entries.findById("hs-one").isEmpty()) {
            AuthorityHeadFixtures.admit(admission, "hs-one", "one.gua.test", ONE);
        }
        if (entries.findById("hs-two").isEmpty()) {
            AuthorityHeadFixtures.admit(admission, "hs-two", "two.gua.test", TWO);
        }
    }

    @Test
    void aHeadThatContradictsAHeldPlacementRecordIsRefused() throws Exception {
        String accountId = AuthorityHeadFixtures.genesisAccountId("placement-disagrees");
        place(accountId, "hs-one", ONE);
        int before = headLeaves().size();

        // hs-two signs correctly with its own ACTIVE roster key, and is refused because the record this node
        // already holds puts the account on hs-one.
        byte[] canonical = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("disagrees"), 1, "hs-two", now());
        mockMvc.perform(post("/account/authority/heads").contentType(MediaType.APPLICATION_JSON)
                        .content(AuthorityHeadFixtures.envelopeJson(canonical, TWO)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("placement_disagrees"));

        assertThat(store.find(accountId)).isEmpty();
        assertThat(headLeaves()).hasSize(before);
    }

    @Test
    void aHeadThatAgreesWithTheHeldPlacementRecordIsAccepted() throws Exception {
        String accountId = AuthorityHeadFixtures.genesisAccountId("placement-agrees");
        place(accountId, "hs-one", ONE);

        byte[] canonical = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("agrees"), 1, "hs-one", now());
        mockMvc.perform(post("/account/authority/heads").contentType(MediaType.APPLICATION_JSON)
                        .content(AuthorityHeadFixtures.envelopeJson(canonical, ONE)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.result").value("stored"));

        assertThat(store.find(accountId)).get()
                .satisfies(row -> assertThat(row.homeserverId()).isEqualTo("hs-one"));
    }

    @Test
    void anAccountWithNoPlacementRecordIsNotTreatedAsContradicted() throws Exception {
        // Absence of a record is absence of evidence. A homeserver that publishes a head before its placement
        // record arrives is not refused for it, and first claim still wins.
        String accountId = AuthorityHeadFixtures.genesisAccountId("placement-absent");
        byte[] canonical = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("absent"), 1, "hs-two", now());

        mockMvc.perform(post("/account/authority/heads").contentType(MediaType.APPLICATION_JSON)
                        .content(AuthorityHeadFixtures.envelopeJson(canonical, TWO)))
                .andExpect(status().isCreated());
    }

    /** Publish a generation-1 placement record putting {@code accountId} on {@code homeserverId}. */
    private void place(String accountId, String homeserverId, Ed25519.KeyPairB64 key) throws Exception {
        Instant issued = now();
        PlacementRecord record = new PlacementRecord(PlacementRecordCodec.VERSION,
                PlacementRecordCodec.GENERATION, accountId,
                PlacementRecord.Origin.of(AccountId.decode(accountId)[1]), homeserverId, issued, issued,
                issued.plus(Duration.ofDays(399)));
        byte[] canonical = PlacementRecordCodec.encode(record);
        String body = "{\"record\":\""
                + Base64.getUrlEncoder().withoutPadding().encodeToString(canonical)
                + "\",\"signature\":\""
                + Ed25519.sign(Ed25519.privateKey(key.privateKeyB64()), canonical) + "\"}";
        mockMvc.perform(post("/placement/records").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated());
    }

    private java.util.List<TransparencyLog.Event> headLeaves() {
        return transparencyLog.eventsOfType(TransparencyLog.ACCOUNT_AUTHORITY);
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MILLIS);
    }
}
