package global.gua.resolver.governance;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.TransparencyLog;
import global.gua.resolver.roster.store.RosterEntryRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The membership epoch path end to end, with governance required: an admission is an intent, a status change
 * is an intent, and only a governance-signed epoch changes what is served.
 *
 * <p>The governance key here is minted in memory for this context. It stands in for a key that, in a real
 * environment, lives on an operator machine and never reaches the resolver.
 */
@SpringBootTest
// Per method, not per class: these tests commit epochs and admit members, so they mutate the very state the
// next one asserts about. The schema script drops and recreates, so a fresh context is a fresh federation.
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class RegistryEpochFlowTest {

    private static final GovernanceFixtures.Holder GOVERNANCE =
            GovernanceFixtures.Holder.of("gov-1", "operator-a");
    private static final GovernanceFixtures.Holder STRANGER =
            GovernanceFixtures.Holder.of("gov-x", "operator-z");
    private static final FederationGenesis GENESIS =
            GovernanceFixtures.singleOperator("gua-epoch-test", GOVERNANCE);
    private static final String GENESIS_ID = CanonicalGenesis.id(GENESIS);

    @DynamicPropertySource
    static void governance(DynamicPropertyRegistry registry) throws Exception {
        Path file = Files.createTempDirectory("gua-genesis").resolve("genesis.json");
        Files.writeString(file, GovernanceFixtures.mapper().writeValueAsString(GENESIS));
        registry.add("spring.datasource.url",
                () -> "jdbc:h2:mem:epoch-flow;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
        registry.add("gua.resolver.genesis.file", file::toString);
        registry.add("gua.resolver.genesis.expected-id", () -> GENESIS_ID);
        registry.add("gua.resolver.governance.required", () -> "true");
    }

    @Autowired RegistryService registry;
    @Autowired AdmissionService admission;
    @Autowired RosterStore rosterStore;
    @Autowired JdbcTransparencyLog transparencyLog;
    @Autowired RosterEntryRepository entries;

    /** Sign whatever the resolver says it is expecting, with the governance key. */
    private RegistryEpoch signPending(List<GovernanceFixtures.Holder> signers) {
        RegistryService.PendingEpoch pending = registry.pending();
        return GovernanceFixtures.epoch(pending.genesisId(), pending.epoch(), pending.previousEpochHash(),
                pending.contentHash(), signers);
    }

    @Test
    void theSeededEntryWaitsInPendingUntilAnEpochAdmitsIt() {
        RosterEntry seeded = entries.findById("dev").orElseThrow();
        assertThat(seeded.status()).isEqualTo(RosterEntry.Status.PENDING);
        assertThat(rosterStore.current().activeEntries()).isEmpty();

        RegistryService.PendingEpoch pending = registry.pending();
        assertThat(pending.genesisId()).isEqualTo(GENESIS_ID);
        assertThat(pending.epoch()).isEqualTo(1);
        assertThat(pending.previousEpochHash()).isEmpty();
        assertThat(pending.content().members()).singleElement()
                .satisfies(m -> assertThat(m.status()).isEqualTo(RosterEntry.Status.ACTIVE));

        long before = transparencyLog.head().size();
        registry.commit(signPending(List.of(GOVERNANCE)), pending.content());

        assertThat(entries.findById("dev").orElseThrow().status()).isEqualTo(RosterEntry.Status.ACTIVE);
        assertThat(rosterStore.current().activeEntries()).hasSize(1);
        assertThat(transparencyLog.head().size()).isEqualTo(before + 1);
        assertThat(transparencyLog.eventsOfType(TransparencyLog.MEMBERSHIP_EPOCH)).isNotEmpty();

        RegistryService.PublishedEpoch published =
                registry.current(Registry.HOMESERVERS).orElseThrow();
        assertThat(published.epoch().epoch()).isEqualTo(1);
        assertThat(published.epochHash())
                .isEqualTo(transparencyLog.eventsOfType(TransparencyLog.MEMBERSHIP_EPOCH)
                        .get(0).payloadHash());
    }

    @Test
    void anEpochSignedByAKeyTheGenesisDoesNotEnumerateIsRefused() {
        RegistryService.PendingEpoch pending = registry.pending();

        assertThatThrownBy(() -> registry.commit(signPending(List.of(STRANGER)), pending.content()))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("from 0 operator(s), need 1");
    }

    @Test
    void anUnsignedEpochIsRefused() {
        RegistryService.PendingEpoch pending = registry.pending();

        assertThatThrownBy(() -> registry.commit(signPending(List.of()), pending.content()))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("need 1");
    }

    @Test
    void anEpochNamingAnotherGenesisIsRefused() {
        RegistryService.PendingEpoch pending = registry.pending();
        RegistryEpoch foreign = GovernanceFixtures.epoch("0".repeat(64), pending.epoch(),
                pending.previousEpochHash(), pending.contentHash(), List.of(GOVERNANCE));

        assertThatThrownBy(() -> registry.commit(foreign, pending.content()))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("pinned to");
    }

    @Test
    void anEpochNumberOutOfSequenceIsRefused() {
        RegistryService.PendingEpoch pending = registry.pending();
        RegistryEpoch skipped = GovernanceFixtures.epoch(pending.genesisId(), 7, "a".repeat(64),
                pending.contentHash(), List.of(GOVERNANCE));

        assertThatThrownBy(() -> registry.commit(skipped, pending.content()))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("expected epoch 1");
    }

    @Test
    void anEpochWhoseContentHashDoesNotMatchItsContentIsRefused() {
        RegistryService.PendingEpoch pending = registry.pending();
        RegistryEpoch mismatched = GovernanceFixtures.epoch(pending.genesisId(), pending.epoch(),
                pending.previousEpochHash(), "b".repeat(64), List.of(GOVERNANCE));

        assertThatThrownBy(() -> registry.commit(mismatched, pending.content()))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("contentHash does not match the content");
    }

    @Test
    void anEpochCarryingAMembershipTheResolverDidNotBuildIsRefused() {
        RegistryService.PendingEpoch pending = registry.pending();
        // Correctly signed, internally consistent, and inventing a member the resolver never proposed.
        HomeserverRegistryContent invented = HomeserverRegistryContent.of(List.of(
                new RegistryMember("smuggled", RosterEntry.Status.ACTIVE, null, 99, true, List.of())));
        RegistryEpoch epoch = GovernanceFixtures.epoch(pending.genesisId(), pending.epoch(),
                pending.previousEpochHash(), CanonicalHomeserverRegistryContent.hash(invented),
                List.of(GOVERNANCE));

        assertThatThrownBy(() -> registry.commit(epoch, invented))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("not the membership this resolver built");
    }

    @Test
    void aSuspendRecordsIntentAndOnlyAnEpochAppliesIt() {
        registry.commit(signPending(List.of(GOVERNANCE)), registry.pending().content());
        assertThat(rosterStore.current().activeEntries()).hasSize(1);

        admission.setStatus("dev", RosterEntry.Status.SUSPENDED);

        // Still ACTIVE and still served: recording the intent is not the act.
        assertThat(entries.findById("dev").orElseThrow().status()).isEqualTo(RosterEntry.Status.ACTIVE);
        assertThat(rosterStore.current().activeEntries()).hasSize(1);
        assertThat(registry.pending().content().members()).singleElement()
                .satisfies(m -> assertThat(m.status()).isEqualTo(RosterEntry.Status.SUSPENDED));

        registry.commit(signPending(List.of(GOVERNANCE)), registry.pending().content());

        assertThat(entries.findById("dev").orElseThrow().status()).isEqualTo(RosterEntry.Status.SUSPENDED);
        assertThat(rosterStore.current().activeEntries()).isEmpty();
    }

    @Test
    void anAdmissionLandsPendingAndCannotBeServedWithoutAnEpoch() {
        String serverName = "governed.gua.global";
        Ed25519.KeyPairB64 key = Ed25519.generate();
        String proof = Ed25519.sign(Ed25519.privateKey(key.privateKeyB64()),
                serverName.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        admission.admit(new global.gua.resolver.admission.AdmissionRequest("governed", serverName,
                "https://" + serverName, "https://account." + serverName, "BR", 1, true,
                key.publicKeyB64(), proof, "dns-txt-proof-token", List.of(), null, null));

        assertThat(entries.findById("governed").orElseThrow().status())
                .isEqualTo(RosterEntry.Status.PENDING);
        assertThat(rosterStore.current().activeEntries())
                .noneSatisfy(e -> assertThat(e.homeserver().id()).isEqualTo("governed"));

        registry.commit(signPending(List.of(GOVERNANCE)), registry.pending().content());

        assertThat(entries.findById("governed").orElseThrow().status())
                .isEqualTo(RosterEntry.Status.ACTIVE);
    }

    @Test
    void theEpochChainContinuesAndAReplayedEpochIsRefused() {
        registry.commit(signPending(List.of(GOVERNANCE)), registry.pending().content());
        RegistryService.PublishedEpoch first = registry.current(Registry.HOMESERVERS).orElseThrow();

        RegistryService.PendingEpoch second = registry.pending();
        assertThat(second.epoch()).isEqualTo(2);
        assertThat(second.previousEpochHash()).isEqualTo(first.epochHash());
        registry.commit(signPending(List.of(GOVERNANCE)), second.content());

        assertThat(registry.current(Registry.HOMESERVERS).orElseThrow().epoch().epoch()).isEqualTo(2);
        assertThat(registry.at(Registry.HOMESERVERS, 1)).isPresent();

        // Re-submitting epoch 2 is now out of sequence: an accepted epoch cannot be replayed.
        RegistryEpoch replay = GovernanceFixtures.epoch(second.genesisId(), 2, second.previousEpochHash(),
                second.contentHash(), List.of(GOVERNANCE));
        assertThatThrownBy(() -> registry.commit(replay, second.content()))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("expected epoch 3");
    }

    @Test
    void anEpochForARegistryWithNoCodePathIsRefused() {
        RegistryService.PendingEpoch pending = registry.pending();
        RegistryEpoch verifierEpoch = new RegistryEpoch(RegistryEpoch.SCHEMA, Registry.VERIFIERS,
                pending.genesisId(), 1, "", Instant.now().truncatedTo(ChronoUnit.MILLIS),
                pending.contentHash(), List.of());

        assertThatThrownBy(() -> registry.commit(
                verifierEpoch.withSignatures(List.of(GOVERNANCE.sign(
                        CanonicalRegistryEpoch.bytes(verifierEpoch)))), pending.content()))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("only HomeserverRegistry has an epoch path");
    }
}
