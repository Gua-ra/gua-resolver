package global.gua.resolver.startup;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import global.gua.resolver.ResolverApplication;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.governance.CanonicalGenesis;
import global.gua.resolver.governance.FederationGenesis;
import global.gua.resolver.governance.GovernanceFixtures;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The fail-closed half of the cutover, pinned rather than left accidental: with governance required, a
 * bundle signed by the operational key does NOT verify, and the service does not come up.
 *
 * <p>The second test is the whole point of the gate. It boots the SAME bundle, signed by the SAME key, from
 * the same file, with {@code gua.resolver.governance.required} flipped to false, and it must start. So the
 * flag, and nothing else, is what decides whether the operational key is a policy trust root. That is the
 * property that was missing when this shipped unconditionally and took an environment down.
 *
 * <p>These boot the application themselves instead of using {@code @SpringBootTest}, because a context that
 * must fail to start cannot be an injected one.
 */
class GovernanceRequiredRefusesOperationalKeyTest {

    private static final GovernanceFixtures.Holder GOVERNANCE =
            GovernanceFixtures.Holder.of("gov-refuse-1", "operator-a");
    private static final FederationGenesis GENESIS =
            GovernanceFixtures.singleOperator("gua-refuse-test", GOVERNANCE);
    private static final String GENESIS_ID = CanonicalGenesis.id(GENESIS);

    private static final Ed25519.KeyPairB64 OPERATIONAL = Ed25519.generate();
    private static final String OPERATIONAL_KEY_ID = "gua-authority-startup";

    /** The bundle an environment is still serving before the re-signing step of the runbook has been done. */
    private static Path operationalKeySignedBundle() throws Exception {
        return StartupPolicyFixtures.write(
                StartupPolicyFixtures.signedBy(StartupPolicyFixtures.ruleless(),
                        OPERATIONAL_KEY_ID, OPERATIONAL.privateKeyB64()),
                "gua-policy-stale");
    }

    private static Path genesisFile() throws Exception {
        Path file = Files.createTempDirectory("gua-genesis-refuse").resolve("genesis.json");
        Files.writeString(file, GovernanceFixtures.mapper().writeValueAsString(GENESIS));
        return file;
    }

    /**
     * Passed as command-line arguments, not {@code SpringApplicationBuilder.properties}, which lands in
     * {@code defaultProperties} BELOW the test {@code application.yml}. That yml carries its own
     * {@code authority.trusted-keys}, so a lower-precedence override is silently ignored and the operational
     * key minted here would never be the one in force.
     */
    private static String[] arguments(Path genesis, Path policy, String database, boolean governanceRequired) {
        return new String[] {
                "--server.port=0",
                "--spring.datasource.url=jdbc:h2:mem:" + database
                        + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
                "--gua.resolver.genesis.file=" + genesis,
                "--gua.resolver.genesis.expected-id=" + GENESIS_ID,
                "--gua.resolver.governance.required=" + governanceRequired,
                "--gua.resolver.authority.signing-key-id=" + OPERATIONAL_KEY_ID,
                "--gua.resolver.authority.signing-private-key=" + OPERATIONAL.privateKeyB64(),
                "--gua.resolver.authority.trusted-keys[0].id=" + OPERATIONAL_KEY_ID,
                "--gua.resolver.authority.trusted-keys[0].public-key=" + OPERATIONAL.publicKeyB64(),
                "--gua.resolver.policy.enabled=true",
                "--gua.resolver.policy.file=" + policy,
                "--gua.resolver.policy.require-signatures=true",
                "--gua.resolver.policy.signature-threshold=1",
        };
    }

    private static ConfigurableApplicationContext boot(String[] arguments) {
        return new SpringApplicationBuilder(ResolverApplication.class)
                .web(WebApplicationType.SERVLET)
                .run(arguments);
    }

    @Test
    void aBundleSignedByTheOperationalKeyStopsStartupWhenGovernanceIsRequired() throws Exception {
        String[] arguments = arguments(genesisFile(), operationalKeySignedBundle(),
                "refuse-operational", true);

        Throwable thrown = org.assertj.core.api.Assertions.catchThrowable(() -> {
            try (ConfigurableApplicationContext context = boot(arguments)) {
                throw new AssertionError("the context started on a bundle no governance key signed");
            }
        });

        assertThat(thrown).isNotNull();
        // Both halves of the real crash-loop message, so this pins the behaviour rather than just "it threw".
        assertThat(StartupPolicyFixtures.causeMessages(thrown))
                .anySatisfy(m -> assertThat(m).contains("no valid routing policy loaded"))
                .anySatisfy(m -> assertThat(m).contains("has 0 valid signatures, need 1"));
    }

    @Test
    void theSameBundleStartsWhenGovernanceIsNotRequired() throws Exception {
        // Same bundle, same operational key, same genesis on disk. Only the flag differs.
        String[] arguments = arguments(genesisFile(), operationalKeySignedBundle(),
                "refuse-operational-ungoverned", false);

        try (ConfigurableApplicationContext context = boot(arguments)) {
            RoutingPolicySource policy = context.getBean(RoutingPolicySource.class);
            assertThat(policy.current()).map(RoutingPolicyBundle::version)
                    .contains(StartupPolicyFixtures.VERSION);
        }
    }
}
