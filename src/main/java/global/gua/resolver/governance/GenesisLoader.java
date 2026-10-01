package global.gua.resolver.governance;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.roster.MemberEntryJson;

@Component
public class GenesisLoader {

    private static final Logger log = LoggerFactory.getLogger(GenesisLoader.class);

    private final FederationGenesis genesis;
    private final List<GovernanceTransition> transitions;
    private final GovernanceKeySet keySet;
    private final String chainHead;
    private final boolean governanceRequired;

    public GenesisLoader(ResolverProperties props, ObjectMapper json) {
        ResolverProperties.Genesis config = props.getGenesis();
        this.governanceRequired = props.getGovernance().isRequired();
        String file = config.getFile();

        if (file == null || file.isBlank()) {
            if (governanceRequired) {
                throw new IllegalStateException("gua.resolver.governance.required is on but no "
                        + "gua.resolver.genesis.file is configured: there would be no governance keys to "
                        + "require a signature from");
            }
            this.genesis = null;
            this.transitions = List.of();
            this.keySet = null;
            this.chainHead = null;
            log.warn("No federation genesis configured (gua.resolver.genesis.file): governance features are "
                    + "off and membership changes take effect on the operational key alone (ADM-001 L10)");
            return;
        }

        this.genesis = readGenesis(json, Path.of(file));
        this.genesis.validateShape();
        String genesisId = CanonicalGenesis.id(this.genesis);
        requireExpectedId(config.getExpectedId(), genesisId);

        GovernanceKeySet loaded = GovernanceKeySet.of(genesisId, this.genesis.threshold(),
                this.genesis.keys());
        GovernanceVerifier.require(loaded, CanonicalGenesis.bytes(this.genesis),
                this.genesis.signatures(), "federation genesis " + genesisId);

        this.transitions = readTransitions(json, config.getTransitionsFile());
        Applied applied = applyTransitions(loaded, genesisId, this.transitions);
        this.keySet = applied.keys();
        this.chainHead = applied.chainHead();
        requireExpectedChainHead(config.getExpectedChainHead(), this.chainHead, this.transitions.size());

        log.info("Loaded federation genesis {} (fingerprint {}) for '{}': {} governance key(s) held by {} "
                        + "operator(s), threshold {}, {} transition(s) applied, chain head {}. "
                        + "Governance required: {}",
                genesisId, CanonicalGenesis.fingerprint(genesisId), this.genesis.federationLabel(),
                this.keySet.keys().size(), this.keySet.operators().size(), this.keySet.threshold(),
                this.transitions.size(), this.chainHead, governanceRequired);
        if (this.keySet.operators().size() == 1) {
            log.info("This genesis names one operator, so governance separates processes and custody, not "
                    + "principals: every independence guarantee still reduces to compromising Gua "
                    + "(ADM-001 standing rule)");
        }
    }

    public boolean configured() {
        return keySet != null;
    }

    public boolean governanceRequired() {
        return governanceRequired;
    }

    public Optional<FederationGenesis> genesis() {
        return Optional.ofNullable(genesis);
    }

    public List<GovernanceTransition> transitions() {
        return transitions;
    }

    public Optional<GovernanceKeySet> keySet() {
        return Optional.ofNullable(keySet);
    }

    public String genesisId() {
        return keySet == null ? null : keySet.genesisId();
    }

    public String chainHead() {
        return chainHead;
    }

    public GovernanceKeySet requireKeySet() {
        if (keySet == null) {
            throw new GovernanceException("no federation genesis is configured on this resolver, so there "
                    + "are no governance keys to verify against");
        }
        return keySet;
    }

    private static FederationGenesis readGenesis(ObjectMapper json, Path path) {
        try {
            return GovernanceJson.read(json, Files.readString(path), FederationGenesis.class);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("cannot read the federation genesis from " + path, e);
        }
    }

    private static void requireExpectedId(String expected, String actual) {
        if (expected == null || expected.isBlank()) {
            return;
        }
        if (!expected.equals(actual)) {
            throw new IllegalStateException("the genesis file has id " + actual + " but "
                    + "gua.resolver.genesis.expected-id pins " + expected
                    + "; refusing to start on an unpinned genesis");
        }
    }

    /** A prefix of a valid chain is valid, so only the pinned head detects a truncated file. */
    private static void requireExpectedChainHead(String expected, String actual, int applied) {
        if (expected == null || expected.isBlank()) {
            if (applied > 0) {
                log.warn("gua.resolver.genesis.expected-chain-head is not set while {} governance key "
                        + "transition(s) are in force: if the transitions file were truncated or removed, "
                        + "this resolver would start on the genesis key set and reinstate a rotated-out "
                        + "key. Pin the current chain head {} (ADM-001 O8)", applied, actual);
            } else {
                log.info("Governance key chain head is {}, the genesis id, with no transition applied. Pin "
                        + "it as gua.resolver.genesis.expected-chain-head to close the downgrade path "
                        + "before the first key rotation", actual);
            }
            return;
        }
        if (!expected.equals(actual)) {
            throw new IllegalStateException("the governance key chain head after " + applied
                    + " transition(s) is " + actual + " but gua.resolver.genesis.expected-chain-head pins "
                    + expected + "; refusing to start on a chain that is not the pinned one");
        }
    }

    private static List<GovernanceTransition> readTransitions(ObjectMapper json, String file) {
        if (file == null || file.isBlank()) {
            return List.of();
        }
        Path path = Path.of(file);
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException("gua.resolver.genesis.transitions-file " + path
                    + " does not exist; leave it unset when there are no transitions");
        }
        com.fasterxml.jackson.databind.JsonNode tree;
        try {
            tree = MemberEntryJson.readTree(json, Files.readString(path));
        } catch (java.io.IOException e) {
            throw new IllegalStateException("cannot read governance transitions from " + path, e);
        }
        if (!tree.isArray()) {
            throw new GovernanceException("the transitions file is a JSON array of "
                    + GovernanceTransition.SCHEMA + " objects, in chain order");
        }
        List<GovernanceTransition> parsed = new ArrayList<>();
        for (com.fasterxml.jackson.databind.JsonNode node : tree) {
            parsed.add(GovernanceJson.read(json, node, GovernanceTransition.class));
        }
        return List.copyOf(parsed);
    }

    private record Applied(GovernanceKeySet keys, String chainHead) {}

    private static Applied applyTransitions(GovernanceKeySet genesisKeys, String genesisId,
                                            List<GovernanceTransition> transitions) {
        GovernanceKeySet current = genesisKeys;
        String previousHash = genesisId;
        long expectedIndex = 1;

        for (GovernanceTransition transition : transitions) {
            transition.validateShape();
            if (!genesisId.equals(transition.genesisId())) {
                throw new GovernanceException("transition " + transition.index() + " names genesis "
                        + transition.genesisId() + ", not the loaded " + genesisId);
            }
            if (transition.index() != expectedIndex) {
                throw new GovernanceException("governance transitions are a chain: expected index "
                        + expectedIndex + ", found " + transition.index());
            }
            if (!previousHash.equals(transition.previousHash())) {
                throw new GovernanceException("transition " + transition.index()
                        + " does not continue the chain: previousHash does not match");
            }

            byte[] canonical = CanonicalGovernanceTransition.bytes(transition);
            GovernanceKeySet next = GovernanceKeySet.of(genesisId, transition.newThreshold(),
                    transition.newKeys());
            GovernanceVerifier.require(current, canonical, transition.signatures(),
                    "transition " + transition.index() + " under the outgoing key set");
            GovernanceVerifier.require(next, canonical, transition.signatures(),
                    "transition " + transition.index() + " under the incoming key set");

            current = next;
            previousHash = CanonicalGovernanceTransition.hash(transition);
            expectedIndex++;
        }
        return new Applied(current, previousHash);
    }
}
