/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.store.RosterEntryRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * What a caller who can reach the public ingest can actually do, and what they cannot.
 *
 * <p>The bound is: they can present records, and every one either verifies under the signing key of an
 * ACTIVE roster entry or is refused. A non-member's signature, a former member's signature and a single
 * flipped byte all land in the same place. Nothing about stored state is reachable without a member key, so
 * the endpoint is not an enumeration oracle either: the last test presents the same unsigned nonsense for an
 * accountId this node holds and one it has never seen, and the two answers are identical.
 */
@SpringBootTest(properties = {
        "gua.resolver.placement.enabled=true",
        "gua.resolver.placement.ingest-enabled=true"
})
@AutoConfigureMockMvc
@DirtiesContext
class PlacementIngestAttackSurfaceTest {

    private static final Ed25519.KeyPairB64 MEMBER = Ed25519.generate();
    private static final Ed25519.KeyPairB64 FORMER = Ed25519.generate();
    private static final Ed25519.KeyPairB64 STRANGER = Ed25519.generate();
    private static final Ed25519.KeyPairB64 SPELLING = Ed25519.generate();

    /** The base64url alphabet, in index order, for building a second spelling of one record. */
    private static final String BASE64URL =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /**
     * Seven characters, so a record naming it is 73 bytes: not a multiple of three, which is the only way
     * padding and trailing bits differ between spellings at all.
     */
    private static final String SPELLING_HS = "hs-sp07";

    @DynamicPropertySource
    static void ownDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () ->
                "jdbc:h2:mem:placement-attack;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
    }

    @Autowired MockMvc mockMvc;
    @Autowired AdmissionService admission;
    @Autowired RosterEntryRepository entries;
    @Autowired JdbcPlacementRecordStore store;

    @BeforeEach
    void admitOneMemberAndOneThatWillBeSuspended() {
        if (entries.findById("hs-one").isEmpty()) {
            PlacementFixtures.admit(admission, "hs-one", "one.gua.test", MEMBER);
        }
        if (entries.findById("hs-old").isEmpty()) {
            PlacementFixtures.admit(admission, "hs-old", "old.gua.test", FORMER);
        }
        if (entries.findById(SPELLING_HS).isEmpty()) {
            PlacementFixtures.admit(admission, SPELLING_HS, "spelling.gua.test", SPELLING);
        }
    }

    @Test
    void aPaddedRecordFieldIsRefusedBecauseItIsNotTheCanonicalSpelling() throws Exception {
        byte[] canonical = PlacementFixtures.canonical(
                PlacementFixtures.genesisAccountId("attack-padded"), SPELLING_HS, now());
        String padded = Base64.getUrlEncoder().encodeToString(canonical);
        assertThat(padded).endsWith("=");

        // The bytes are fine and the signature over them verifies. Only the spelling is wrong, and the
        // field is documented as unpadded base64url, so this is where that contract is asserted.
        present(PlacementFixtures.envelope(padded, PlacementFixtures.sign(canonical, SPELLING)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("bad_base64"));
    }

    @Test
    void aSecondSpellingOfTheSameRecordBytesIsRefused() throws Exception {
        byte[] canonical = PlacementFixtures.canonical(
                PlacementFixtures.genesisAccountId("attack-trailing-bits"), SPELLING_HS, now());
        String signature = PlacementFixtures.sign(canonical, SPELLING);
        String canonicalSpelling = PlacementFixtures.recordB64(canonical);

        // The last character carries four unused bits, so fifteen other characters decode to these same
        // bytes. A decoder that ignores them accepts sixteen spellings of one record, which is the defect
        // ADM-008 decision 2 refuses for the accountId and which the transport should not reintroduce.
        char last = canonicalSpelling.charAt(canonicalSpelling.length() - 1);
        assertThat(BASE64URL.indexOf(last) % 16).isZero();
        String otherSpelling = canonicalSpelling.substring(0, canonicalSpelling.length() - 1)
                + BASE64URL.charAt(BASE64URL.indexOf(last) + 1);
        assertThat(otherSpelling).isNotEqualTo(canonicalSpelling);
        assertThat(Base64.getUrlDecoder().decode(otherSpelling)).containsExactly(canonical);

        present(PlacementFixtures.envelope(otherSpelling, signature))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("bad_base64"));
    }

    @Test
    void aRecordSignedByANonMemberIsRefused() throws Exception {
        // The stranger's key is a perfectly good Ed25519 key. It is simply in no roster entry.
        present(PlacementFixtures.envelope(PlacementFixtures.canonical(
                PlacementFixtures.genesisAccountId("attack-stranger"), "hs-one", now()), STRANGER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("bad_signature"));
    }

    @Test
    void aRecordNamingAHomeserverThatIsNotInTheRosterIsRefused() throws Exception {
        present(PlacementFixtures.envelope(PlacementFixtures.canonical(
                PlacementFixtures.genesisAccountId("attack-unknown-hs"), "hs-nope", now()), STRANGER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("unknown_homeserver"));
    }

    @Test
    void aRecordFromAFormerlyActiveMemberIsRefused() throws Exception {
        // While it is ACTIVE, its records are accepted.
        present(PlacementFixtures.envelope(PlacementFixtures.canonical(
                PlacementFixtures.genesisAccountId("attack-while-active"), "hs-old", now()), FORMER))
                .andExpect(status().isCreated());

        admission.setStatus("hs-old", RosterEntry.Status.SUSPENDED);

        // The roster is read at acceptance time, so the same signer is now refused.
        present(PlacementFixtures.envelope(PlacementFixtures.canonical(
                PlacementFixtures.genesisAccountId("attack-after-suspend"), "hs-old", now()), FORMER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("homeserver_not_active"));
    }

    @Test
    void aTamperedByteIsRefused() throws Exception {
        byte[] canonical = PlacementFixtures.canonical(
                PlacementFixtures.genesisAccountId("attack-tamper"), "hs-one", now());
        String signature = PlacementFixtures.sign(canonical, MEMBER);
        canonical[30] ^= 0x01;   // one bit of the account hash, after signing

        present(PlacementFixtures.envelope(PlacementFixtures.recordB64(canonical), signature))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("bad_signature"));
    }

    @Test
    void repointingARecordAtAnotherHomeserverBreaksItsSignature() throws Exception {
        byte[] canonical = PlacementFixtures.canonical(
                PlacementFixtures.genesisAccountId("attack-repoint"), "hs-one", now());
        String signature = PlacementFixtures.sign(canonical, MEMBER);
        System.arraycopy("hs-old".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0,
                canonical, 42, 6);

        present(PlacementFixtures.envelope(PlacementFixtures.recordB64(canonical), signature))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("bad_signature"));
    }

    @Test
    void anExpiredRecordIsRefused() throws Exception {
        Instant longAgo = now().minus(Duration.ofDays(500));

        present(signedBy(MEMBER, "attack-expired", longAgo, longAgo,
                longAgo.plus(PlacementFixtures.VALIDITY)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("expired"));
    }

    @Test
    void aRecordThatIsNotYetValidIsRefused() throws Exception {
        Instant now = now();

        present(signedBy(MEMBER, "attack-early", now, now.plus(Duration.ofDays(1)),
                now.plus(Duration.ofDays(300))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("not_yet_valid"));
    }

    @Test
    void aRecordIssuedInTheFutureIsRefused() throws Exception {
        // Otherwise one record could freeze an account's slot against every later re-issue, since the
        // re-issue rule orders on issuedAt.
        Instant now = now();

        present(signedBy(MEMBER, "attack-future", now.plus(Duration.ofDays(1)),
                now.minus(Duration.ofHours(1)), now.plus(Duration.ofDays(300))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("issued_in_the_future"));
    }

    @Test
    void aValidityWindowBeyondTheCapIsRefused() throws Exception {
        Instant now = now();

        present(signedBy(MEMBER, "attack-long-window", now, now, now.plus(Duration.ofDays(401))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("window_too_long"));
    }

    @Test
    void aMalformedEnvelopeIsRefusedWithoutReachingTheRoster() throws Exception {
        present("{\"record\":\"not base64url!\",\"signature\":\"AAAA\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("bad_base64"));

        present("{\"record\":\"\",\"signature\":\"\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("malformed_envelope"));

        // Strict transport parsing: an unknown field is refused rather than dropped.
        present("{\"record\":\"AAAA\",\"signature\":\"AAAA\",\"homeserverId\":\"hs-one\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("malformed_envelope"));
    }

    @Test
    void ingestRevealsNothingAboutWhatIsAlreadyStored() throws Exception {
        String stored = PlacementFixtures.genesisAccountId("attack-oracle-stored");
        String neverSeen = PlacementFixtures.genesisAccountId("attack-oracle-unknown");
        present(PlacementFixtures.envelope(
                PlacementFixtures.canonical(stored, "hs-one", now()), MEMBER))
                .andExpect(status().isCreated());
        assertThat(store.find(stored)).isPresent();
        assertThat(store.find(neverSeen)).isEmpty();

        // A caller without a member key gets the same answer for an account this node holds and one it has
        // never seen: the storage rules are only reached after the signature check.
        MvcResult held = present(PlacementFixtures.envelope(
                PlacementFixtures.canonical(stored, "hs-one", now()), STRANGER)).andReturn();
        MvcResult unheld = present(PlacementFixtures.envelope(
                PlacementFixtures.canonical(neverSeen, "hs-one", now()), STRANGER)).andReturn();

        assertThat(held.getResponse().getStatus()).isEqualTo(unheld.getResponse().getStatus());
        assertThat(held.getResponse().getContentAsString())
                .isEqualTo(unheld.getResponse().getContentAsString())
                .contains("bad_signature");
    }

    private String signedBy(Ed25519.KeyPairB64 key, String seed, Instant issuedAt, Instant notBefore,
                            Instant notAfter) {
        PlacementRecord record = new PlacementRecord(PlacementRecordCodec.VERSION,
                PlacementRecordCodec.GENERATION, PlacementFixtures.genesisAccountId(seed),
                PlacementRecord.Origin.GENESIS, "hs-one", issuedAt, notBefore, notAfter);
        return PlacementFixtures.envelope(PlacementRecordCodec.encode(record), key);
    }

    private ResultActions present(String body) throws Exception {
        return mockMvc.perform(post("/placement/records")
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MILLIS);
    }
}
