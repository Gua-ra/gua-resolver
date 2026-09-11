package global.gua.resolver.governance;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.config.ResolverProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Loading the pinned genesis. The failures here are deliberately startup failures rather than degraded
 * running: an unverifiable or unpinned trust root is worse than none, because everything downstream would
 * still look signed.
 */
class GenesisLoaderTest {

    private static final ObjectMapper JSON = GovernanceFixtures.mapper();

    @TempDir
    Path dir;

    private ResolverProperties props(Path genesisFile, String expectedId, boolean governanceRequired)
            throws Exception {
        ResolverProperties props = new ResolverProperties();
        props.getGenesis().setFile(genesisFile == null ? null : genesisFile.toString());
        props.getGenesis().setExpectedId(expectedId);
        props.getGovernance().setRequired(governanceRequired);
        return props;
    }

    private GenesisLoader load(Path genesisFile, String expectedId) throws Exception {
        return new GenesisLoader(props(genesisFile, expectedId, false), JSON);
    }

    @Test
    void loadsAVerifiedGenesisAndExposesItsKeySet() throws Exception {
        GovernanceFixtures.Holder holder = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        FederationGenesis genesis = GovernanceFixtures.singleOperator("gua-test", holder);
        Path file = GovernanceFixtures.write(dir, "genesis.json", genesis);

        GenesisLoader loader = load(file, CanonicalGenesis.id(genesis));

        assertThat(loader.configured()).isTrue();
        assertThat(loader.genesisId()).isEqualTo(CanonicalGenesis.id(genesis));
        assertThat(loader.requireKeySet().threshold()).isEqualTo(1);
        assertThat(loader.requireKeySet().operators()).containsExactly("operator-a");
        assertThat(loader.transitions()).isEmpty();
    }

    @Test
    void withNoGenesisConfiguredGovernanceIsSimplyOff() throws Exception {
        GenesisLoader loader = load(null, null);

        assertThat(loader.configured()).isFalse();
        assertThat(loader.genesis()).isEmpty();
        assertThat(loader.genesisId()).isNull();
        assertThatThrownBy(loader::requireKeySet)
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("no federation genesis is configured");
    }

    @Test
    void requiringGovernanceWithoutAGenesisRefusesToStart() throws Exception {
        assertThatThrownBy(() -> new GenesisLoader(props(null, null, true), JSON))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no").hasMessageContaining("genesis.file is configured");
    }

    @Test
    void aGenesisThatDoesNotMatchThePinRefusesToStart() throws Exception {
        GovernanceFixtures.Holder holder = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        Path file = GovernanceFixtures.write(dir, "genesis.json",
                GovernanceFixtures.singleOperator("gua-test", holder));

        // The file verifies perfectly against its own keys. The pin is what catches the swap.
        assertThatThrownBy(() -> load(file, "0".repeat(64)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("refusing to start on an unpinned genesis");
    }

    @Test
    void aGenesisSignedByTheWrongKeyIsRefused() throws Exception {
        GovernanceFixtures.Holder enumerated = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        GovernanceFixtures.Holder stranger = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        FederationGenesis genesis = GovernanceFixtures.signed(
                GovernanceFixtures.genesis("gua-test", 1, List.of(enumerated)), List.of(stranger));
        Path file = GovernanceFixtures.write(dir, "genesis.json", genesis);

        assertThatThrownBy(() -> load(file, null))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("from 0 operator(s), need 1");
    }

    @Test
    void anUnsignedGenesisIsRefused() throws Exception {
        GovernanceFixtures.Holder holder = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        Path file = GovernanceFixtures.write(dir, "genesis.json",
                GovernanceFixtures.genesis("gua-test", 1, List.of(holder)));

        assertThatThrownBy(() -> load(file, null))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("need 1");
    }

    @Test
    void aGenesisMissingARegistryIsRefused() throws Exception {
        GovernanceFixtures.Holder holder = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        FederationGenesis partial = new FederationGenesis(FederationGenesis.SCHEMA, "gua-test",
                Instant.parse("2026-09-01T00:00:00Z"), FederationGenesis.HASH_SUITE, 1,
                List.of(holder.key()), List.of("HomeserverRegistry"), List.of());
        Path file = GovernanceFixtures.write(dir, "genesis.json",
                GovernanceFixtures.signed(partial, List.of(holder)));

        assertThatThrownBy(() -> load(file, null))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("enumerates exactly");
    }

    @Test
    void anUnknownFieldInTheGenesisFileIsRefusedRatherThanIgnored() throws Exception {
        GovernanceFixtures.Holder holder = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        String document = JSON.writeValueAsString(
                GovernanceFixtures.singleOperator("gua-test", holder))
                .replace("\"threshold\":1", "\"threshold\":1,\"extra\":true");
        Path file = dir.resolve("genesis.json");
        Files.writeString(file, document);

        assertThatThrownBy(() -> load(file, null))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("does not parse strictly");
    }

    @Test
    void aTransitionChainIsAppliedAndAGapIsRefused() throws Exception {
        GovernanceFixtures.Holder outgoing = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        GovernanceFixtures.Holder incoming = GovernanceFixtures.Holder.of("gov-2", "operator-a");
        FederationGenesis genesis = GovernanceFixtures.singleOperator("gua-test", outgoing);
        String genesisId = CanonicalGenesis.id(genesis);
        Path genesisFile = GovernanceFixtures.write(dir, "genesis.json", genesis);

        GovernanceTransition unsigned = new GovernanceTransition(GovernanceTransition.SCHEMA, genesisId, 1,
                genesisId, Instant.parse("2026-10-01T00:00:00Z"), 1, List.of(incoming.key()), List.of());
        byte[] canonical = CanonicalGovernanceTransition.bytes(unsigned);
        GovernanceTransition signed = unsigned.withSignatures(
                List.of(outgoing.sign(canonical), incoming.sign(canonical)));

        Path transitions = dir.resolve("transitions.json");
        Files.writeString(transitions, JSON.writeValueAsString(List.of(signed)));

        ResolverProperties props = props(genesisFile, genesisId, false);
        props.getGenesis().setTransitionsFile(transitions.toString());
        GenesisLoader loader = new GenesisLoader(props, JSON);

        // The key set in force is the transition's, and the genesis id is unchanged: the chain moved, the root did not.
        assertThat(loader.requireKeySet().keys()).extracting(GovernanceKey::keyId).containsExactly("gov-2");
        assertThat(loader.genesisId()).isEqualTo(genesisId);
        assertThat(loader.transitions()).hasSize(1);

        // Index 2 with nothing at index 1 is a gap, not a chain.
        GovernanceTransition gap = new GovernanceTransition(GovernanceTransition.SCHEMA, genesisId, 2,
                genesisId, Instant.parse("2026-10-02T00:00:00Z"), 1, List.of(incoming.key()), List.of());
        byte[] gapBytes = CanonicalGovernanceTransition.bytes(gap);
        Files.writeString(transitions, JSON.writeValueAsString(List.of(
                gap.withSignatures(List.of(outgoing.sign(gapBytes), incoming.sign(gapBytes))))));

        assertThatThrownBy(() -> new GenesisLoader(props, JSON))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("expected index 1");
    }

    @Test
    void withNoTransitionsTheChainHeadIsTheGenesisIdAndCanBePinned() throws Exception {
        GovernanceFixtures.Holder holder = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        FederationGenesis genesis = GovernanceFixtures.singleOperator("gua-test", holder);
        String genesisId = CanonicalGenesis.id(genesis);
        Path file = GovernanceFixtures.write(dir, "genesis.json", genesis);

        ResolverProperties props = props(file, genesisId, false);
        props.getGenesis().setExpectedChainHead(genesisId);

        assertThat(new GenesisLoader(props, JSON).chainHead()).isEqualTo(genesisId);
    }

    @Test
    void aTruncatedTransitionChainIsRefusedWhenTheHeadIsPinned() throws Exception {
        GovernanceFixtures.Holder outgoing = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        GovernanceFixtures.Holder incoming = GovernanceFixtures.Holder.of("gov-2", "operator-a");
        FederationGenesis genesis = GovernanceFixtures.singleOperator("gua-test", outgoing);
        String genesisId = CanonicalGenesis.id(genesis);
        Path genesisFile = GovernanceFixtures.write(dir, "genesis.json", genesis);

        GovernanceTransition unsigned = new GovernanceTransition(GovernanceTransition.SCHEMA, genesisId, 1,
                genesisId, Instant.parse("2026-10-01T00:00:00Z"), 1, List.of(incoming.key()), List.of());
        byte[] canonical = CanonicalGovernanceTransition.bytes(unsigned);
        GovernanceTransition signed = unsigned.withSignatures(
                List.of(outgoing.sign(canonical), incoming.sign(canonical)));
        String head = CanonicalGovernanceTransition.hash(signed);

        Path transitions = dir.resolve("transitions.json");
        Files.writeString(transitions, JSON.writeValueAsString(List.of(signed)));
        ResolverProperties props = props(genesisFile, genesisId, false);
        props.getGenesis().setTransitionsFile(transitions.toString());
        props.getGenesis().setExpectedChainHead(head);

        GenesisLoader loaded = new GenesisLoader(props, JSON);
        assertThat(loaded.chainHead()).isEqualTo(head);
        assertThat(loaded.requireKeySet().keys()).extracting(GovernanceKey::keyId).containsExactly("gov-2");

        // A truncated chain is not a broken chain: the empty one is well formed, and it leaves in force the
        // very key set gov-2 replaced. Only the head pin catches it.
        Files.writeString(transitions, "[]");

        assertThatThrownBy(() -> new GenesisLoader(props, JSON))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("refusing to start on a chain that is not the pinned one");

        // Unpinned, the downgrade goes through and the rotated-out key is back in force. That is the hole.
        props.getGenesis().setExpectedChainHead(null);
        assertThat(new GenesisLoader(props, JSON).requireKeySet().keys())
                .extracting(GovernanceKey::keyId).containsExactly("gov-1");
    }

    @Test
    void theRegistryNamesMayArriveInAnyOrder() throws Exception {
        GovernanceFixtures.Holder holder = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        FederationGenesis declared = GovernanceFixtures.singleOperator("gua-test", holder);
        List<String> sorted = Registry.allWireNames().stream().sorted().toList();
        assertThat(sorted).isNotEqualTo(Registry.allWireNames());

        FederationGenesis reordered = GovernanceFixtures.signed(
                new FederationGenesis(FederationGenesis.SCHEMA, "gua-test",
                        Instant.parse("2026-09-01T00:00:00Z"), FederationGenesis.HASH_SUITE, 1,
                        List.of(holder.key()), sorted, List.of()), List.of(holder));
        String genesisId = CanonicalGenesis.id(declared);

        // The canonical bytes encode the registries as a set, so these two files are the same object and a
        // client that emits them sorted is not serving a different genesis.
        assertThat(CanonicalGenesis.id(reordered)).isEqualTo(genesisId);
        assertThat(load(GovernanceFixtures.write(dir, "reordered.json", reordered), genesisId).configured())
                .isTrue();
    }

    @Test
    void aDuplicatedRegistryNameIsRefused() throws Exception {
        GovernanceFixtures.Holder holder = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        FederationGenesis duplicated = new FederationGenesis(FederationGenesis.SCHEMA, "gua-test",
                Instant.parse("2026-09-01T00:00:00Z"), FederationGenesis.HASH_SUITE, 1,
                List.of(holder.key()),
                List.of("HomeserverRegistry", "HomeserverRegistry", "VerifierRegistry", "PolicyRegistry",
                        "WitnessRegistry"), List.of());
        Path file = GovernanceFixtures.write(dir, "duplicated.json", duplicated);

        assertThatThrownBy(() -> load(file, null))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("without duplicates");
    }

    @Test
    void aTransitionTheIncomingKeySetDidNotSignIsRefused() throws Exception {
        GovernanceFixtures.Holder outgoing = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        GovernanceFixtures.Holder incoming = GovernanceFixtures.Holder.of("gov-2", "operator-a");
        FederationGenesis genesis = GovernanceFixtures.singleOperator("gua-test", outgoing);
        String genesisId = CanonicalGenesis.id(genesis);
        Path genesisFile = GovernanceFixtures.write(dir, "genesis.json", genesis);

        GovernanceTransition unsigned = new GovernanceTransition(GovernanceTransition.SCHEMA, genesisId, 1,
                genesisId, Instant.parse("2026-10-01T00:00:00Z"), 1, List.of(incoming.key()), List.of());
        // Only the outgoing set signs: the change is authorised, but nothing proves the new key is held.
        GovernanceTransition halfSigned = unsigned.withSignatures(
                List.of(outgoing.sign(CanonicalGovernanceTransition.bytes(unsigned))));

        Path transitions = dir.resolve("transitions.json");
        Files.writeString(transitions, JSON.writeValueAsString(List.of(halfSigned)));
        ResolverProperties props = props(genesisFile, genesisId, false);
        props.getGenesis().setTransitionsFile(transitions.toString());

        assertThatThrownBy(() -> new GenesisLoader(props, JSON))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("incoming key set");
    }
}
