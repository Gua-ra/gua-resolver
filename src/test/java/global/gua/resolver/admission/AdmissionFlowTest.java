package global.gua.resolver.admission;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.placement.ClaimPredicate;
import global.gua.resolver.roster.CanonicalMemberEntry;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.MemberAttestation;
import global.gua.resolver.roster.MemberEntrySigner;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.RosterVerifier;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;
import global.gua.resolver.roster.store.RosterEntryRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * End-to-end admission against the real authority stack: admitting a homeserver vets its key-possession +
 * domain proof, appends an ADMIT event to the transparency log, and re-signs a roster that still verifies;
 * overlapping claims are rejected. It also covers the member self-signed path (ADM-007): admission that
 * proves possession by signing its own entry, the attest endpoint that lets an admitted member adopt, move
 * or re-key its entry, and the substitutions that must fail. Dirties the context so its writes don't leak
 * into other @SpringBootTests.
 */
@SpringBootTest
@DirtiesContext
class AdmissionFlowTest {

    /** The seeded dev homeserver's membership key, generated in memory for this context only. */
    private static final Ed25519.KeyPairB64 DEV_KEY = Ed25519.generate();

    @DynamicPropertySource
    static void seededDevHomeserver(DynamicPropertyRegistry registry) {
        // Its own database: this context reseeds the roster, and the shared one is used by other tests.
        registry.add("spring.datasource.url",
                () -> "jdbc:h2:mem:admission-flow;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
        registry.add("gua.resolver.dev-homeserver.signing-key", DEV_KEY::publicKeyB64);
    }

    @Autowired RosterStore rosterStore;
    @Autowired RosterVerifier verifier;
    @Autowired AdmissionService admission;
    @Autowired JdbcTransparencyLog transparencyLog;
    @Autowired RosterEntryRepository entries;

    private static final Instant NOT_BEFORE = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant NOT_AFTER = NOT_BEFORE.plus(Duration.ofDays(400));

    private AdmissionRequest request(String serverName, List<ClaimPredicate> claims) {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        String proof = Ed25519.sign(Ed25519.privateKey(kp.privateKeyB64()),
                serverName.getBytes(StandardCharsets.UTF_8));
        return new AdmissionRequest(null, serverName, "https://" + serverName,
                "https://account." + serverName, "BR", 1, true,
                kp.publicKeyB64(), proof, "dns-txt-proof-token", claims, null, null);
    }

    private static Homeserver homeserver(String id, String serverName, String baseUrl, String signingKey) {
        return new Homeserver(id, serverName, baseUrl, "https://account." + serverName, "BR", 1, true,
                signingKey, Homeserver.SearchVisibility.GLOBAL, List.of());
    }

    private static MemberAttestation attestation(Homeserver hs, String keyId, long sequence,
                                                 Ed25519.KeyPairB64 key) {
        MemberAttestation unsigned = new MemberAttestation(CanonicalMemberEntry.SCHEMA,
                CanonicalMemberEntry.ALG, keyId, sequence, NOT_BEFORE, NOT_AFTER, List.of());
        return MemberEntrySigner.sign(hs, unsigned, keyId, key.privateKeyB64());
    }

    /** Admit {@code id} with a member self-signature over exactly the fields being registered. */
    private RosterEntry admitSelfSigned(String id, String serverName, Ed25519.KeyPairB64 key, String keyId) {
        Homeserver hs = homeserver(id, serverName, "https://" + serverName, key.publicKeyB64());
        MemberAttestation member = attestation(hs, keyId, 1, key);
        admission.admit(new AdmissionRequest(id, serverName, hs.baseUrl(), hs.masIssuer(), hs.region(),
                1, true, key.publicKeyB64(), null, "dns-txt-proof-token", List.of(), null, null, member));
        return entries.findById(id).orElseThrow();
    }

    private static MemberAttestationRequest attestRequest(Homeserver hs, MemberAttestation member) {
        return new MemberAttestationRequest(new MemberAttestationRequest.HomeserverFields(hs.id(),
                hs.serverName(), hs.baseUrl(), hs.masIssuer(), hs.signingKey(), hs.region(),
                hs.searchVisibility(), hs.searchGroups()), member);
    }

    @Test
    void admittingGrowsTheLogAndKeepsTheRosterVerifiable() {
        long before = rosterStore.current().logCheckpoint().size();

        SignedRoster after = admission.admit(request("usp.gua.global",
                List.of(new ClaimPredicate(null, null, null, null, "usp.br", null, null, 100))));

        assertThat(after.logCheckpoint().size()).isEqualTo(before + 1);
        assertThat(after.entries()).anySatisfy(e ->
                assertThat(e.homeserver().serverName()).isEqualTo("usp.gua.global"));
        assertThat(verifier.isVerified(after)).isTrue();
    }

    @Test
    void rejectsKeyPossessionForgery() {
        AdmissionRequest good = request("forge.gua.global", List.of());
        AdmissionRequest forged = new AdmissionRequest(null, good.serverName(), good.baseUrl(),
                good.masIssuer(), good.region(), good.weight(), good.acceptsNew(),
                good.signingKey(), Ed25519.generate().publicKeyB64(),  // proof not made by signingKey
                good.domainProof(), good.claims(), null, null);

        assertThatThrownBy(() -> admission.admit(forged))
                .isInstanceOf(AdmissionService.AdmissionException.class);
    }

    @Test
    void admissionDefaultsToGlobalSearchVisibility() {
        SignedRoster after = admission.admit(request("defaultvis.gua.global", List.of()));

        assertThat(after.entries()).anySatisfy(e -> {
            if (e.homeserver().serverName().equals("defaultvis.gua.global")) {
                assertThat(e.homeserver().searchVisibility())
                        .isEqualTo(Homeserver.SearchVisibility.GLOBAL);
                assertThat(e.homeserver().searchGroups()).isEmpty();
            }
        });
    }

    @Test
    void admissionCarriesGroupSearchVisibilityIntoTheSignedRoster() {
        AdmissionRequest base = request("grouped.gua.global", List.of());
        AdmissionRequest grouped = new AdmissionRequest(base.id(), base.serverName(), base.baseUrl(),
                base.masIssuer(), base.region(), base.weight(), base.acceptsNew(), base.signingKey(),
                base.keyPossessionProof(), base.domainProof(), base.claims(),
                "group", List.of("edu-br"));

        SignedRoster after = admission.admit(grouped);

        assertThat(after.entries()).anySatisfy(e -> {
            if (e.homeserver().serverName().equals("grouped.gua.global")) {
                assertThat(e.homeserver().searchVisibility())
                        .isEqualTo(Homeserver.SearchVisibility.GROUP);
                assertThat(e.homeserver().searchGroups()).containsExactly("edu-br");
            }
        });
        // the visibility policy is inside the signed bytes: roster still verifies
        assertThat(verifier.isVerified(after)).isTrue();
    }

    @Test
    void rejectsGroupVisibilityWithoutGroupsAndGroupsWithoutGroupVisibility() {
        AdmissionRequest base = request("badvis.gua.global", List.of());
        AdmissionRequest groupNoGroups = new AdmissionRequest(base.id(), base.serverName(),
                base.baseUrl(), base.masIssuer(), base.region(), base.weight(), base.acceptsNew(),
                base.signingKey(), base.keyPossessionProof(), base.domainProof(), base.claims(),
                "GROUP", List.of());
        assertThatThrownBy(() -> admission.admit(groupNoGroups))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("requires at least one search group");

        AdmissionRequest groupsNoGroup = new AdmissionRequest(base.id(), base.serverName(),
                base.baseUrl(), base.masIssuer(), base.region(), base.weight(), base.acceptsNew(),
                base.signingKey(), base.keyPossessionProof(), base.domainProof(), base.claims(),
                "server", List.of("edu-br"));
        assertThatThrownBy(() -> admission.admit(groupsNoGroup))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("only valid with searchVisibility GROUP");
    }

    @Test
    void rejectsOverlappingClaims() {
        ClaimPredicate vivo = new ClaimPredicate(null, "72411", null, null, null, null, null, 100);
        admission.admit(request("vivo.gua.global", List.of(vivo)));

        // A second homeserver claiming the same MCCMNC must be refused.
        assertThatThrownBy(() ->
                admission.admit(request("vivo2.gua.global", List.of(
                        new ClaimPredicate(null, "72411", null, null, null, null, null, 100)))))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("overlap");
    }

    @Test
    void legacyAdmissionIsAcceptedWithTheFlagOffAndLeavesTheEntryUnattested() {
        admission.admit(request("legacy.gua.global", List.of()));

        RosterEntry entry = entries.findAll().stream()
                .filter(e -> e.homeserver().serverName().equals("legacy.gua.global")).findFirst()
                .orElseThrow();
        assertThat(entry.member()).isNull();
        assertThat(rosterStore.current().entries()).contains(entry);
    }

    @Test
    void admissionWithAMemberBlockNeedsNoPossessionProofAndCommitsToTheSignedBytes() {
        Ed25519.KeyPairB64 key = Ed25519.generate();
        long before = rosterStore.current().logCheckpoint().size();

        RosterEntry admitted = admitSelfSigned("selfsigned", "selfsigned.gua.global", key, "selfsigned-1");

        assertThat(admitted.member()).isNotNull();
        assertThat(admitted.member().sequence()).isEqualTo(1);
        // ADMIT and MEMBER_ATTEST: an admission carrying a member block appends two leaves.
        assertThat(rosterStore.current().logCheckpoint().size()).isEqualTo(before + 2);
        String hash = CanonicalMemberEntry.hash(admitted.homeserver(), admitted.member());
        assertThat(transparencyLog.eventsOfType(TransparencyLog.MEMBER_ATTEST))
                .anySatisfy(e -> {
                    assertThat(e.homeserverId()).isEqualTo("selfsigned");
                    assertThat(e.payloadHash()).isEqualTo(hash);
                });
        assertThat(entries.memberHistory("selfsigned")).singleElement()
                .satisfies(row -> assertThat(row.entryHash()).isEqualTo(hash));
        assertThat(verifier.isVerified(rosterStore.current())).isTrue();
    }

    @Test
    void admissionRejectsAMemberSignatureOverDifferentFields() {
        Ed25519.KeyPairB64 key = Ed25519.generate();
        Homeserver signedFields = homeserver("substituted", "substituted.gua.global",
                "https://matrix.substituted.gua.global", key.publicKeyB64());
        MemberAttestation member = attestation(signedFields, "substituted-1", 1, key);

        assertThatThrownBy(() -> admission.admit(new AdmissionRequest("substituted",
                "substituted.gua.global", "https://attacker.gua.global", signedFields.masIssuer(),
                signedFields.region(), 1, true, key.publicKeyB64(), null, "dns-txt-proof-token",
                List.of(), null, null, member)))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("does not verify");
    }

    @Test
    void attestingTheSeededEntryAdoptsItAndLogsTheAcceptedBytes() {
        SignedRoster.LogCheckpoint before = transparencyLog.head();
        Homeserver attested = new Homeserver("dev", "gua.local", "https://matrix2.gua.local",
                "https://account.gua.local", "dev", 1, true, DEV_KEY.publicKeyB64(),
                Homeserver.SearchVisibility.GLOBAL, List.of());
        MemberAttestation member = attestation(attested, "dev-1", 1, DEV_KEY);

        SignedRoster after = admission.attest("dev", attestRequest(attested, member));

        RosterEntry dev = entries.findById("dev").orElseThrow();
        assertThat(dev.member().keyId()).isEqualTo("dev-1");
        assertThat(dev.homeserver().baseUrl()).isEqualTo("https://matrix2.gua.local");
        assertThat(after.entries()).anySatisfy(e -> {
            if (e.homeserver().id().equals("dev")) {
                assertThat(e.member()).isNotNull();
            }
        });
        String hash = CanonicalMemberEntry.hash(dev.homeserver(), dev.member());
        assertThat(entries.memberHistory("dev")).singleElement().satisfies(row -> {
            assertThat(row.sequence()).isEqualTo(1);
            assertThat(row.entryHash()).isEqualTo(hash);
            assertThat(row.logLeafIndex()).isNotNull();
        });
        assertThat(transparencyLog.verifyConsistency(before, transparencyLog.head())).isTrue();
        assertThat(verifier.isVerified(after)).isTrue();
    }

    @Test
    void attestRefusesASubstitutedBaseUrlAServerNameChangeAndAStaleSequence() {
        Ed25519.KeyPairB64 key = Ed25519.generate();
        RosterEntry admitted = admitSelfSigned("attestrules", "attestrules.gua.global", key, "attestrules-1");
        Homeserver signed = new Homeserver("attestrules", "attestrules.gua.global",
                "https://moved.attestrules.gua.global", admitted.homeserver().masIssuer(), "BR", 1, true,
                key.publicKeyB64(), Homeserver.SearchVisibility.GLOBAL, List.of());
        MemberAttestation member = attestation(signed, "attestrules-1", 2, key);

        MemberAttestationRequest substituted = attestRequest(
                new Homeserver(signed.id(), signed.serverName(), "https://attacker.gua.global",
                        signed.masIssuer(), signed.region(), 1, true, signed.signingKey(),
                        signed.searchVisibility(), signed.searchGroups()), member);
        assertThatThrownBy(() -> admission.attest("attestrules", substituted))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("does not verify");

        MemberAttestationRequest renamed = attestRequest(
                new Homeserver(signed.id(), "other.gua.global", signed.baseUrl(), signed.masIssuer(),
                        signed.region(), 1, true, signed.signingKey(), signed.searchVisibility(),
                        signed.searchGroups()), member);
        assertThatThrownBy(() -> admission.attest("attestrules", renamed))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("serverName cannot change");

        MemberAttestation stale = attestation(signed, "attestrules-1", 1, key);
        assertThatThrownBy(() -> admission.attest("attestrules", attestRequest(signed, stale)))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("sequence must be greater");

        // The valid update goes through, and only then.
        assertThat(admission.attest("attestrules", attestRequest(signed, member))).isNotNull();
        assertThat(entries.findById("attestrules").orElseThrow().homeserver().baseUrl())
                .isEqualTo("https://moved.attestrules.gua.global");
    }

    @Test
    void aKeyRotationNeedsBothKeysAndAdvancesTheChain() {
        Ed25519.KeyPairB64 first = Ed25519.generate();
        Ed25519.KeyPairB64 second = Ed25519.generate();
        admitSelfSigned("rotating", "rotating.gua.global", first, "rotating-1");

        Homeserver rotated = homeserver("rotating", "rotating.gua.global", "https://rotating.gua.global",
                second.publicKeyB64());
        MemberAttestation onlyNew = attestation(rotated, "rotating-2", 2, second);
        assertThatThrownBy(() -> admission.attest("rotating", attestRequest(rotated, onlyNew)))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("not signed by the previous key");

        MemberAttestation dualSigned = MemberEntrySigner.sign(rotated, onlyNew, "rotating-1",
                first.privateKeyB64());
        admission.attest("rotating", attestRequest(rotated, dualSigned));

        RosterEntry entry = entries.findById("rotating").orElseThrow();
        assertThat(entry.homeserver().signingKey()).isEqualTo(second.publicKeyB64());
        assertThat(entry.member().keyId()).isEqualTo("rotating-2");
        assertThat(entries.memberHistory("rotating")).hasSize(2)
                .extracting(RosterEntryRepository.MemberHistoryRow::sequence)
                .containsExactly(1L, 2L);
    }

    @Test
    void aRevokedMemberIsNotReAttested() {
        Ed25519.KeyPairB64 key = Ed25519.generate();
        admitSelfSigned("revoked", "revoked.gua.global", key, "revoked-1");
        admission.setStatus("revoked", RosterEntry.Status.REVOKED);

        Homeserver hs = homeserver("revoked", "revoked.gua.global", "https://revoked.gua.global",
                key.publicKeyB64());
        MemberAttestation member = attestation(hs, "revoked-2", 2, key);

        assertThatThrownBy(() -> admission.attest("revoked", attestRequest(hs, member)))
                .isInstanceOf(AdmissionService.AdmissionException.class)
                .hasMessageContaining("admitted afresh");
    }
}
