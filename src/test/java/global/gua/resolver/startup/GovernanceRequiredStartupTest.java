package global.gua.resolver.startup;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.governance.CanonicalGenesis;
import global.gua.resolver.governance.FederationGenesis;
import global.gua.resolver.governance.GenesisLoader;
import global.gua.resolver.governance.GovernanceFixtures;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The other side of the cutover, booted as a whole application: governance required, a pinned genesis, and a
 * policy bundle signed by the governance key. It must start and serve, and the trust root in force must be
 * the governance key set rather than the operational one.
 *
 * <p>This is the state an environment reaches after the key ceremony and the re-signing step in
 * docs/runbooks/governance-keys.md. The governance key is minted in memory here; in a real environment it
 * lives on an operator machine and the resolver never holds it.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext
class GovernanceRequiredStartupTest {

    private static final GovernanceFixtures.Holder GOVERNANCE =
            GovernanceFixtures.Holder.of("gov-startup-1", "operator-a");
    private static final FederationGenesis GENESIS =
            GovernanceFixtures.singleOperator("gua-startup-test", GOVERNANCE);
    private static final String GENESIS_ID = CanonicalGenesis.id(GENESIS);

    /** Configured and trusted for the roster, and deliberately NOT what the policy bundle is signed with. */
    private static final Ed25519.KeyPairB64 OPERATIONAL = Ed25519.generate();
    private static final String OPERATIONAL_KEY_ID = "gua-authority-startup";

    @DynamicPropertySource
    static void governed(DynamicPropertyRegistry registry) throws Exception {
        Path genesisFile = Files.createTempDirectory("gua-genesis-startup").resolve("genesis.json");
        Files.writeString(genesisFile, GovernanceFixtures.mapper().writeValueAsString(GENESIS));

        RoutingPolicyBundle bundle = StartupPolicyFixtures.signedBy(StartupPolicyFixtures.ruleless(),
                GOVERNANCE.key().keyId(), GOVERNANCE.privateKeyB64());
        Path policyFile = StartupPolicyFixtures.write(bundle, "gua-policy-governed");

        registry.add("spring.datasource.url",
                () -> "jdbc:h2:mem:governed-trust-root;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
        registry.add("gua.resolver.genesis.file", genesisFile::toString);
        registry.add("gua.resolver.genesis.expected-id", () -> GENESIS_ID);
        registry.add("gua.resolver.governance.required", () -> "true");
        registry.add("gua.resolver.authority.signing-key-id", () -> OPERATIONAL_KEY_ID);
        registry.add("gua.resolver.authority.signing-private-key", OPERATIONAL::privateKeyB64);
        registry.add("gua.resolver.authority.trusted-keys[0].id", () -> OPERATIONAL_KEY_ID);
        registry.add("gua.resolver.authority.trusted-keys[0].public-key", OPERATIONAL::publicKeyB64);
        registry.add("gua.resolver.policy.enabled", () -> "true");
        registry.add("gua.resolver.policy.file", policyFile::toString);
        registry.add("gua.resolver.policy.require-signatures", () -> "true");
        registry.add("gua.resolver.policy.signature-threshold", () -> "1");
    }

    @Autowired MockMvc mockMvc;
    @Autowired ResolverProperties props;
    @Autowired GenesisLoader genesis;
    @Autowired RoutingPolicySource policySource;

    @Test
    void theContextStartsWithGovernanceInForce() {
        assertThat(props.getGovernance().isRequired()).isTrue();
        assertThat(genesis.configured()).isTrue();
        assertThat(genesis.genesisId()).isEqualTo(GENESIS_ID);
        assertThat(genesis.chainHead()).isEqualTo(GENESIS_ID);
    }

    @Test
    void theGovernanceSignedBundleIsLoadedAndServed() throws Exception {
        assertThat(policySource.current()).map(RoutingPolicyBundle::version)
                .contains(StartupPolicyFixtures.VERSION);

        mockMvc.perform(get("/policy/routing/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].available").value(true));
    }

    @Test
    void theGenesisItVerifiesUnderIsTheOneItPublishes() throws Exception {
        mockMvc.perform(get("/.well-known/gua-federation"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.genesisId").value(GENESIS_ID))
                .andExpect(jsonPath("$.genesis.keys[0].keyId").value(GOVERNANCE.key().keyId()));
    }
}
