/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

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
import org.springframework.test.web.servlet.ResultActions;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;
import global.gua.resolver.roster.store.RosterEntryRepository;
import global.gua.resolver.verify.AccountAuthorityHeadCheck;
import global.gua.resolver.verify.ResolverVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The publication path end to end (ADM-009 decision 12): accept a head from the homeserver entitled to publish
 * it, anchor it in the transparency log under the log's existing rules, serve what a verifier needs, and have
 * the verifier this repo owns accept it against the signed roster.
 *
 * <p>The test that matters most is {@link #theServedProofVerifiesAgainstTheSignedRoster()}: it takes the proof
 * off the wire, the roster off the wire, the authority public key from configuration as a client would pin it,
 * and runs the real verifier. Nothing in it is constructed by the test except the head a homeserver published.
 *
 * <p>The leaf counts are asserted throughout, because the log size is the roster version and new-account
 * fallback placement seeds on it (ADM-001 L6): one leaf per accepted publication is the agreed cost, and a
 * retry or a refused head costing a leaf would be a defect.
 */
@SpringBootTest(properties = {
        "gua.resolver.account-authority.enabled=true",
        "gua.resolver.account-authority.ingest-enabled=true"
})
@AutoConfigureMockMvc
@DirtiesContext
class AccountAuthorityHeadPublicationTest {

    private static final Ed25519.KeyPairB64 ONE = Ed25519.generate();
    private static final Ed25519.KeyPairB64 TWO = Ed25519.generate();

    @DynamicPropertySource
    static void ownDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () ->
                "jdbc:h2:mem:authority-head;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
    }

    @Autowired MockMvc mockMvc;
    @Autowired AdmissionService admission;
    @Autowired RosterEntryRepository entries;
    @Autowired JdbcAccountAuthorityHeadStore store;
    @Autowired JdbcTransparencyLog transparencyLog;
    @Autowired ResolverProperties props;
    @Autowired ObjectMapper json;

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
    void aPublishedHeadIsStoredVerbatimAndAnchoredWithOneLeaf() throws Exception {
        String accountId = AuthorityHeadFixtures.bootstrapAccountId("publish-ok");
        byte[] canonical = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("h1"), 1, "hs-one", now());
        String recordB64 = AuthorityHeadFixtures.recordB64(canonical);
        String signature = AuthorityHeadFixtures.sign(canonical, ONE);
        int before = headLeaves().size();

        publish(AuthorityHeadFixtures.json(recordB64, signature))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.result").value("stored"));

        // Verbatim: the bytes that were signed are the bytes that are served, not a re-encoding of them.
        mockMvc.perform(get("/account/authority/heads/" + accountId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.record").value(recordB64))
                .andExpect(jsonPath("$.signature").value(signature));

        List<TransparencyLog.Event> leaves = headLeaves();
        assertThat(leaves).hasSize(before + 1);
        TransparencyLog.Event leaf = leaves.get(leaves.size() - 1);
        // The leaf commits the SHA-256 of the received bytes and names the publisher, and nothing else: no
        // accountId reaches the log's own columns.
        assertThat(leaf.payloadHash()).isEqualTo(MerkleTree.sha256Hex(canonical));
        assertThat(leaf.homeserverId()).isEqualTo("hs-one");
        assertThat(store.find(accountId)).isPresent()
                .get()
                .satisfies(row -> {
                    assertThat(row.headSeq()).isEqualTo(1);
                    assertThat(row.logLeafIndex()).isEqualTo(leaf.index());
                });
    }

    @Test
    void theServedProofVerifiesAgainstTheSignedRoster() throws Exception {
        String accountId = AuthorityHeadFixtures.bootstrapAccountId("verify-e2e");
        String headHash = AuthorityHeadFixtures.headHash("verify-e2e-head");
        byte[] canonical = AuthorityHeadFixtures.canonical(accountId, headHash, 3, "hs-one", now());
        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(canonical),
                AuthorityHeadFixtures.sign(canonical, ONE)))
                .andExpect(status().isCreated());

        AccountAuthorityHeadProof proof = read(
                get("/account/authority/heads/" + accountId + "/proof"), AccountAuthorityHeadProof.class);
        SignedRoster roster = read(get("/roster"), SignedRoster.class);

        // The client's trust root: the published authority keys and the threshold, pinned out of band. Nothing
        // else in this verification comes from the resolver unverified.
        ResolverVerifier verifier = new ResolverVerifier(props.getAuthority().getTrustedKeys(),
                props.getAuthority().getThreshold(), List.of(), 1);
        AccountAuthorityHeadCheck.Result result = verifier.verifyAccountAuthorityHead(
                new AccountAuthorityHeadCheck.Expected(accountId, headHash, 3), proof,
                AccountAuthorityHeadCheck.Consistency.none(), roster, Instant.now());

        assertThat(result.head().homeserverId()).isEqualTo("hs-one");
        assertThat(result.head().headSeq()).isEqualTo(3);
        assertThat(result.checkpoint()).isEqualTo(roster.logCheckpoint());
        assertThat(proof.leaf().type()).isEqualTo(TransparencyLog.ACCOUNT_AUTHORITY);
        // The proof is built against the checkpoint the signed roster commits to, so the ordinary case needs no
        // consistency step at all.
        assertThat(proof.checkpoint()).isEqualTo(roster.logCheckpoint());
    }

    @Test
    void aRetryOfTheSameHeadCostsNoSecondLeaf() throws Exception {
        String accountId = AuthorityHeadFixtures.bootstrapAccountId("retry");
        byte[] canonical = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("retry-head"), 2, "hs-one", now());
        String body = AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(canonical),
                AuthorityHeadFixtures.sign(canonical, ONE));

        publish(body).andExpect(status().isCreated());
        int after = headLeaves().size();
        publish(body).andExpect(status().isOk()).andExpect(jsonPath("$.result").value("unchanged"));

        assertThat(headLeaves()).hasSize(after);
    }

    @Test
    void aNewerHeadReplacesTheStoredOneAndIsAnchoredOnItsOwnLeaf() throws Exception {
        String accountId = AuthorityHeadFixtures.bootstrapAccountId("forward");
        Instant issued = now();
        byte[] first = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("forward-1"), 1, "hs-one", issued);
        byte[] second = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("forward-2"), 2, "hs-one", issued.plusSeconds(1));

        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(first),
                AuthorityHeadFixtures.sign(first, ONE))).andExpect(status().isCreated());
        int after = headLeaves().size();
        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(second),
                AuthorityHeadFixtures.sign(second, ONE)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("replaced"));

        assertThat(headLeaves()).hasSize(after + 1);
        assertThat(store.find(accountId)).get()
                .satisfies(row -> {
                    assertThat(row.headSeq()).isEqualTo(2);
                    assertThat(row.recordB64()).isEqualTo(AuthorityHeadFixtures.recordB64(second));
                    assertThat(row.logLeafIndex()).isNotNull();
                });
        // And the new head's own proof verifies, so a reader that follows the account forward never has to trust
        // the transition itself, only that each head it was shown was logged.
        AccountAuthorityHeadProof proof = read(
                get("/account/authority/heads/" + accountId + "/proof"), AccountAuthorityHeadProof.class);
        assertThat(proof.leaf().payloadHash()).isEqualTo(MerkleTree.sha256Hex(second));
    }

    @Test
    void theSameHeadRepublishedWithAFreshWindowMovesForward() throws Exception {
        // A head does not change when a window is refreshed, but the object does, and a reader refuses an
        // expired one. So an equal sequence number with a newer issuedAt has to be accepted, or a publisher
        // could never keep a head from going stale.
        String accountId = AuthorityHeadFixtures.bootstrapAccountId("refresh");
        String headHash = AuthorityHeadFixtures.headHash("refresh-head");
        Instant issued = now();
        byte[] first = AuthorityHeadFixtures.canonical(accountId, headHash, 9, "hs-one", issued);
        byte[] refreshed = AuthorityHeadFixtures.canonical(accountId, headHash, 9, "hs-one",
                issued.plusSeconds(30));

        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(first),
                AuthorityHeadFixtures.sign(first, ONE))).andExpect(status().isCreated());
        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(refreshed),
                AuthorityHeadFixtures.sign(refreshed, ONE)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("replaced"));

        assertThat(store.find(accountId)).get()
                .satisfies(row -> assertThat(row.issuedAt()).isEqualTo(issued.plusSeconds(30)));
    }

    @Test
    void anOlderHeadIsRefusedAndTheStoredHeadStands() throws Exception {
        String accountId = AuthorityHeadFixtures.bootstrapAccountId("stale");
        Instant issued = now();
        byte[] current = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("stale-5"), 5, "hs-one", issued);
        byte[] older = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("stale-4"), 4, "hs-one", issued.plusSeconds(1));

        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(current),
                AuthorityHeadFixtures.sign(current, ONE))).andExpect(status().isCreated());
        int after = headLeaves().size();

        // A newer issuedAt does not buy an older sequence number: the chain is what orders heads.
        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(older),
                AuthorityHeadFixtures.sign(older, ONE)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("stale_head"));

        assertThat(headLeaves()).hasSize(after);
        assertThat(store.find(accountId)).get()
                .satisfies(row -> assertThat(row.headSeq()).isEqualTo(5));
    }

    @Test
    void anotherHomeserverCannotPublishForAnAccountThatAlreadyHasAHead() throws Exception {
        String accountId = AuthorityHeadFixtures.bootstrapAccountId("conflict");
        Instant issued = now();
        byte[] mine = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("conflict-1"), 1, "hs-one", issued);
        byte[] theirs = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("conflict-2"), 2, "hs-two", issued);

        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(mine),
                AuthorityHeadFixtures.sign(mine, ONE))).andExpect(status().isCreated());
        int after = headLeaves().size();

        // hs-two signs correctly with its own ACTIVE roster key, and is still refused: one account has one home,
        // and a higher sequence number does not let a second member take it over.
        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(theirs),
                AuthorityHeadFixtures.sign(theirs, TWO)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("authority_conflict"));

        assertThat(headLeaves()).hasSize(after);
        assertThat(store.find(accountId)).get()
                .satisfies(row -> assertThat(row.homeserverId()).isEqualTo("hs-one"));
    }

    @Test
    void aHeadSignedByAMemberOtherThanTheOneItNamesIsRefusedWithoutALeaf() throws Exception {
        String accountId = AuthorityHeadFixtures.bootstrapAccountId("wrong-signer");
        byte[] canonical = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("wrong-signer-head"), 1, "hs-one", now());
        int before = headLeaves().size();

        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(canonical),
                AuthorityHeadFixtures.sign(canonical, TWO)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("bad_signature"));

        assertThat(headLeaves()).hasSize(before);
        assertThat(store.find(accountId)).isEmpty();
    }

    @Test
    void aHeadNamingAHomeserverTheRosterDoesNotCarryIsRefused() throws Exception {
        String accountId = AuthorityHeadFixtures.bootstrapAccountId("unknown-hs");
        byte[] canonical = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("unknown-head"), 1, "hs-nowhere", now());

        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(canonical),
                AuthorityHeadFixtures.sign(canonical, ONE)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("unknown_homeserver"));
    }

    @Test
    void aNonCanonicalTransportSpellingIsRefusedRatherThanDecoded() throws Exception {
        String accountId = AuthorityHeadFixtures.bootstrapAccountId("padded");
        byte[] canonical = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash("padded-head"), 1, "hs-one", now());
        // Padding where the one canonical spelling allows none. The signature would verify over these same
        // bytes, which is exactly why the spelling is refused rather than normalised: one head, one transport
        // form, so a retry cannot arrive looking like a different object.
        String padded = AuthorityHeadFixtures.recordB64(canonical) + "=";

        publish(AuthorityHeadFixtures.json(padded, AuthorityHeadFixtures.sign(canonical, ONE)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("bad_base64"));

        // And a spelling outside the alphabet altogether.
        publish(AuthorityHeadFixtures.json(AuthorityHeadFixtures.recordB64(canonical).replace('A', '+'),
                AuthorityHeadFixtures.sign(canonical, ONE)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("bad_base64"));
    }

    @Test
    void nothingIsServedForAnAccountWithNoPublishedHead() throws Exception {
        mockMvc.perform(get("/account/authority/heads/"
                        + AuthorityHeadFixtures.bootstrapAccountId("absent")))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("no_authority_head"));
        mockMvc.perform(get("/account/authority/heads/"
                        + AuthorityHeadFixtures.bootstrapAccountId("absent") + "/proof"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("no_authority_head"));
        // Not a canonical accountId: refused as a bad query, never looked up.
        mockMvc.perform(get("/account/authority/heads/ga1notanaccount"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_account_id"));
    }

    private ResultActions publish(String body) throws Exception {
        return mockMvc.perform(post("/account/authority/heads")
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private <T> T read(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request,
                       Class<T> type) throws Exception {
        String body = mockMvc.perform(request).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readValue(body, type);
    }

    private List<TransparencyLog.Event> headLeaves() {
        return transparencyLog.eventsOfType(TransparencyLog.ACCOUNT_AUTHORITY);
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MILLIS);
    }
}
