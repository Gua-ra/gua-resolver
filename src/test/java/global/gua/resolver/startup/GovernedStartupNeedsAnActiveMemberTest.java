package global.gua.resolver.startup;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import global.gua.resolver.ResolverApplication;
import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.governance.CanonicalGenesis;
import global.gua.resolver.governance.FederationGenesis;
import global.gua.resolver.governance.GovernanceFixtures;
import global.gua.resolver.policy.RoutingPolicyBundle;
import global.gua.resolver.policy.RoutingPolicySource;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** A database must first boot with governance not required, so an ACTIVE member exists for the bundle. */
class GovernedStartupNeedsAnActiveMemberTest {

    private static final GovernanceFixtures.Holder GOVERNANCE =
            GovernanceFixtures.Holder.of("gov-bootstrap-1", "operator-a");
    private static final FederationGenesis GENESIS =
            GovernanceFixtures.singleOperator("gua-bootstrap-test", GOVERNANCE);
    private static final String GENESIS_ID = CanonicalGenesis.id(GENESIS);

    private static final Ed25519.KeyPairB64 OPERATIONAL = Ed25519.generate();
    private static final Ed25519.KeyPairB64 DELEGATE = Ed25519.generate();
    private static final String OPERATIONAL_KEY_ID = "gua-authority-startup";

    private static final String SEEDED_MEMBER = "dev";

    private static Path governanceSignedBundle() throws Exception {
        return StartupPolicyFixtures.write(
                StartupPolicyFixtures.signedBy(StartupPolicyFixtures.routingTo(SEEDED_MEMBER, DELEGATE),
                        GOVERNANCE.key().keyId(), GOVERNANCE.privateKeyB64()),
                "gua-policy-governed-targeting");
    }

    private static Path operationalSignedBundle() throws Exception {
        return StartupPolicyFixtures.write(
                StartupPolicyFixtures.signedBy(StartupPolicyFixtures.routingTo(SEEDED_MEMBER, DELEGATE),
                        OPERATIONAL_KEY_ID, OPERATIONAL.privateKeyB64()),
                "gua-policy-operational-targeting");
    }

    private static Path genesisFile() throws Exception {
        Path file = Files.createTempDirectory("gua-genesis-bootstrap").resolve("genesis.json");
        Files.writeString(file, GovernanceFixtures.mapper().writeValueAsString(GENESIS));
        return file;
    }

    private static String jdbcUrl(String database) {
        return "jdbc:h2:mem:" + database + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE";
    }

    /** createSchema is true only on the first boot of a database: the schema script drops first. */
    private static String[] arguments(String database, boolean governanceRequired, Path genesis,
                                      Path policy, boolean policyEnabled, boolean createSchema) {
        List<String> arguments = new ArrayList<>(List.of(
                "--server.port=0",
                "--spring.datasource.url=" + jdbcUrl(database),
                "--spring.sql.init.mode=" + (createSchema ? "always" : "never"),
                "--gua.resolver.genesis.file=" + genesis,
                "--gua.resolver.genesis.expected-id=" + GENESIS_ID,
                "--gua.resolver.governance.required=" + governanceRequired,
                "--gua.resolver.authority.signing-key-id=" + OPERATIONAL_KEY_ID,
                "--gua.resolver.authority.signing-private-key=" + OPERATIONAL.privateKeyB64(),
                "--gua.resolver.authority.trusted-keys[0].id=" + OPERATIONAL_KEY_ID,
                "--gua.resolver.authority.trusted-keys[0].public-key=" + OPERATIONAL.publicKeyB64(),
                "--gua.resolver.policy.enabled=" + policyEnabled,
                "--gua.resolver.policy.require-signatures=true",
                "--gua.resolver.policy.signature-threshold=1"));
        if (policy != null) {
            arguments.add("--gua.resolver.policy.file=" + policy);
        }
        return arguments.toArray(String[]::new);
    }

    private static ConfigurableApplicationContext boot(String[] arguments) {
        return new SpringApplicationBuilder(ResolverApplication.class)
                .web(WebApplicationType.SERVLET)
                .run(arguments);
    }

    private static List<String> bootExpectingFailure(String[] arguments) {
        Throwable thrown = catchThrowable(() -> {
            try (ConfigurableApplicationContext context = boot(arguments)) {
                throw new AssertionError("the context started when it should not have");
            }
        });
        assertThat(thrown).isNotNull();
        return StartupPolicyFixtures.causeMessages(thrown);
    }

    private static String statusInDatabase(String database, String homeserverId) throws Exception {
        try (Connection connection = DriverManager.getConnection(jdbcUrl(database), "sa", "");
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT status FROM roster_entry WHERE id = '" + homeserverId + "'")) {
            return rows.next() ? rows.getString(1) : null;
        }
    }

    @Test
    void aFreshDatabaseWhoseFirstBootAlreadyRequiresGovernanceDoesNotStart() throws Exception {
        String database = "bootstrap-deadlock";

        List<String> messages = bootExpectingFailure(arguments(database, true, genesisFile(),
                governanceSignedBundle(), true, true));

        assertThat(messages)
                .anySatisfy(m -> assertThat(m).contains("no valid routing policy loaded"))
                .anySatisfy(m -> assertThat(m)
                        .contains("references unknown or inactive homeserver " + SEEDED_MEMBER));

        assertThat(statusInDatabase(database, SEEDED_MEMBER)).isEqualTo("PENDING");
    }

    @Test
    void theFlagFlipAloneDoesNotRecoverADatabaseThatAlreadySeededPending() throws Exception {
        String database = "bootstrap-flag-flip";
        Path genesis = genesisFile();

        bootExpectingFailure(arguments(database, true, genesis, governanceSignedBundle(), true, true));
        assertThat(statusInDatabase(database, SEEDED_MEMBER)).isEqualTo("PENDING");

        // The seed only happens on an empty database, so the PENDING row survives the flag flip.
        List<String> messages = bootExpectingFailure(
                arguments(database, false, genesis, operationalSignedBundle(), true, false));

        assertThat(messages)
                .anySatisfy(m -> assertThat(m).contains("no valid routing policy loaded"))
                .anySatisfy(m -> assertThat(m)
                        .contains("references unknown or inactive homeserver " + SEEDED_MEMBER));
        assertThat(statusInDatabase(database, SEEDED_MEMBER)).isEqualTo("PENDING");
    }

    @Test
    void theRecoveryIsToStartWithoutPolicyAndPromoteTheSeededMember() throws Exception {
        String database = "bootstrap-recovery";
        Path genesis = genesisFile();

        bootExpectingFailure(arguments(database, true, genesis, governanceSignedBundle(), true, true));

        // With policy off there is no FileRoutingPolicySource bean to throw.
        try (ConfigurableApplicationContext recovery =
                     boot(arguments(database, false, genesis, null, false, false))) {
            recovery.getBean(AdmissionService.class).setStatus(SEEDED_MEMBER, RosterEntry.Status.ACTIVE);
        }
        assertThat(statusInDatabase(database, SEEDED_MEMBER)).isEqualTo("ACTIVE");

        try (ConfigurableApplicationContext governed =
                     boot(arguments(database, true, genesis, governanceSignedBundle(), true, false))) {
            assertThat(governed.getBean(RoutingPolicySource.class).current())
                    .map(RoutingPolicyBundle::version).contains(StartupPolicyFixtures.VERSION);
        }
    }

    @Test
    void theRunbookOrderNeverReachesTheDeadlock() throws Exception {
        String database = "bootstrap-runbook-order";
        Path genesis = genesisFile();

        try (ConfigurableApplicationContext beforeCutover =
                     boot(arguments(database, false, genesis, operationalSignedBundle(), true, true))) {
            assertThat(beforeCutover.getBean(RoutingPolicySource.class).current())
                    .map(RoutingPolicyBundle::version).contains(StartupPolicyFixtures.VERSION);
        }
        assertThat(statusInDatabase(database, SEEDED_MEMBER)).isEqualTo("ACTIVE");

        try (ConfigurableApplicationContext afterCutover =
                     boot(arguments(database, true, genesis, governanceSignedBundle(), true, false))) {
            assertThat(afterCutover.getBean(RoutingPolicySource.class).current())
                    .map(RoutingPolicyBundle::version).contains(StartupPolicyFixtures.VERSION);

            assertThat(afterCutover.getBean(RosterStore.class).current().entries())
                    .anySatisfy(entry -> assertThat(entry.homeserver().id()).isEqualTo(SEEDED_MEMBER));
        }
    }
}
