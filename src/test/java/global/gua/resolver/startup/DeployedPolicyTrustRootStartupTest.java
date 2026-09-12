package global.gua.resolver.startup;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The shape a deployed environment actually runs, booted as a whole application: a routing policy bundle
 * signed with the OPERATIONAL key, no federation genesis, and governance not required. It must start and it
 * must serve.
 *
 * <p>This test exists because Phase 2 shipped once without it. The fail-closed trust root was applied
 * unconditionally, so this configuration stopped verifying its own policy bundle,
 * {@code FileRoutingPolicySource} threw inside its constructor, the context never started, and the pod
 * crash-looped on "no valid routing policy loaded". Every unit test passed, including one asserting that
 * governance was off by default, because none of them booted the application with the configuration the
 * environment runs. A verifier's trust root is a startup-time decision, so only a startup-time test can
 * hold it.
 *
 * <p>Nothing here is read from an environment: the operational key is minted in memory and the bundle it
 * signs is written to a temporary file.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext
class DeployedPolicyTrustRootStartupTest {

    /** The operational key: it signs the roster, and in this shape it also signed the policy bundle. */
    private static final Ed25519.KeyPairB64 OPERATIONAL = Ed25519.generate();
    private static final Ed25519.KeyPairB64 DELEGATE = Ed25519.generate();
    private static final String OPERATIONAL_KEY_ID = "gua-authority-startup";

    @DynamicPropertySource
    static void deployedShape(DynamicPropertyRegistry registry) throws Exception {
        RoutingPolicyBundle bundle = StartupPolicyFixtures.signedBy(
                StartupPolicyFixtures.routingTo("dev", DELEGATE),
                OPERATIONAL_KEY_ID, OPERATIONAL.privateKeyB64());
        Path file = StartupPolicyFixtures.write(bundle, "gua-policy-deployed");

        registry.add("spring.datasource.url",
                () -> "jdbc:h2:mem:deployed-trust-root;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
        registry.add("gua.resolver.authority.signing-key-id", () -> OPERATIONAL_KEY_ID);
        registry.add("gua.resolver.authority.signing-private-key", OPERATIONAL::privateKeyB64);
        registry.add("gua.resolver.authority.trusted-keys[0].id", () -> OPERATIONAL_KEY_ID);
        registry.add("gua.resolver.authority.trusted-keys[0].public-key", OPERATIONAL::publicKeyB64);
        registry.add("gua.resolver.policy.enabled", () -> "true");
        registry.add("gua.resolver.policy.file", file::toString);
        registry.add("gua.resolver.policy.require-signatures", () -> "true");
        registry.add("gua.resolver.policy.signature-threshold", () -> "1");
        // Deliberately NOT set, because the deployed environment does not set them: no
        // gua.resolver.policy.trusted-keys, no gua.resolver.genesis.file, no
        // gua.resolver.governance.required. The bundle verifies through the fallback to the operational key
        // set, which is what this configuration has always relied on.
    }

    @Autowired MockMvc mockMvc;
    @Autowired ResolverProperties props;
    @Autowired RoutingPolicySource policySource;

    @Test
    void theConfigurationUnderTestIsTheUngovernedOneWithNoPolicyTrustRootOfItsOwn() {
        // If either of these drifts, the rest of this class stops testing the deployed shape.
        assertThat(props.getGovernance().isRequired()).isFalse();
        assertThat(props.getPolicy().getTrustedKeys()).isEmpty();
        assertThat(props.getGenesis().getFile()).isNullOrEmpty();
    }

    @Test
    void theOperationalKeySignedBundleIsLoadedAndServed() throws Exception {
        assertThat(policySource.current()).map(RoutingPolicyBundle::version)
                .contains(StartupPolicyFixtures.VERSION);

        mockMvc.perform(get("/policy/routing/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].available").value(true))
                .andExpect(jsonPath("$[0].version").value(StartupPolicyFixtures.VERSION));
    }

    @Test
    void aRequestInTheDelegatedZoneIsRoutedByTheSignedPolicy() throws Exception {
        // Serving, not merely starting: the rule inside the delegate-signed zone is what answers.
        mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"" + StartupPolicyFixtures.PHONE_IN_ZONE + "\",\"trace\":true}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false))
                .andExpect(jsonPath("$.registerAt.serverName").value("gua.local"))
                .andExpect(jsonPath("$.trace.rule").value("PolicyRoutingRule"))
                .andExpect(jsonPath("$.trace.homeserverId").value("dev"))
                .andExpect(jsonPath("$.trace.policyId").value(StartupPolicyFixtures.POLICY_ID))
                .andExpect(jsonPath("$.trace.delegatedZoneId").value(StartupPolicyFixtures.ZONE_ID));
    }

    @Test
    void theRosterStillSignsAndVerifiesUnderTheSameOperationalKey() throws Exception {
        mockMvc.perform(get("/roster"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entries[0].homeserver.id").value("dev"))
                .andExpect(jsonPath("$.authoritySignatures[0].authorityKeyId").value(OPERATIONAL_KEY_ID));
    }
}
