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

/**
 * A startup failure that depends on roster state rather than on which key signed the bundle.
 *
 * <p>A policy bundle may only name homeservers that are ACTIVE in the roster, and
 * {@code FileRoutingPolicySource} validates against the roster before it checks signatures. With governance
 * required, the seeded member is PENDING and stays out of the signed roster, so on a database whose first
 * boot already has the flag on, a bundle that targets that member fails validation and startup fails.
 *
 * <p>So the first boot of a database has to happen with the flag off (docs/runbooks/governance-keys.md).
 * Flipping the flag back is not sufficient once the seed has landed PENDING, because the seed only happens
 * on an empty database.
 */
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

    /** What a deployment mounts after the cutover: a bundle with a zone and a rule, governance-signed. */
    private static Path governanceSignedBundle() throws Exception {
        return StartupPolicyFixtures.write(
                StartupPolicyFixtures.signedBy(StartupPolicyFixtures.routingTo(SEEDED_MEMBER, DELEGATE),
                        GOVERNANCE.key().keyId(), GOVERNANCE.privateKeyB64()),
                "gua-policy-governed-targeting");
    }

    /** The same bundle an environment serves before the cutover: same zone and rule, operational-signed. */
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

    /**
     * Command-line arguments, not {@code SpringApplicationBuilder.properties}, which lands below the test
     * {@code application.yml} and would be ignored for the keys that yml already sets.
     *
     * @param createSchema true on the first boot of a database. The test schema script is DROP-first, so a
     *                     later boot has to skip it or it would wipe exactly the rows under test.
     */
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

    /** Boot expecting failure, and return every message down the cause chain. */
    private static List<String> bootExpectingFailure(String[] arguments) {
        Throwable thrown = catchThrowable(() -> {
            try (ConfigurableApplicationContext context = boot(arguments)) {
                throw new AssertionError("the context started when it should not have");
            }
        });
        assertThat(thrown).isNotNull();
        return StartupPolicyFixtures.causeMessages(thrown);
    }

    /** Read a status straight out of the database, which outlives the context that failed to start. */
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

        // The bundle is signed by a governance key, so this is not the signature path: validation against the
        // roster runs first, and the seeded member is not in it.
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

        // Policy off is what gets a process up at all: FileRoutingPolicySource is conditional on
        // policy.enabled, so with it false there is no bean to throw. With the flag also off, a status
        // change takes effect immediately instead of only recording intent.
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

        // Genesis mounted, flag off: a fresh database seeds its member ACTIVE, and the bundle the environment
        // is already serving verifies through the pre-cutover fallback.
        try (ConfigurableApplicationContext beforeCutover =
                     boot(arguments(database, false, genesis, operationalSignedBundle(), true, true))) {
            assertThat(beforeCutover.getBean(RoutingPolicySource.class).current())
                    .map(RoutingPolicyBundle::version).contains(StartupPolicyFixtures.VERSION);
        }
        assertThat(statusInDatabase(database, SEEDED_MEMBER)).isEqualTo("ACTIVE");

        // The re-signed bundle, the flag on, the same database: it has to start.
        try (ConfigurableApplicationContext afterCutover =
                     boot(arguments(database, true, genesis, governanceSignedBundle(), true, false))) {
            assertThat(afterCutover.getBean(RoutingPolicySource.class).current())
                    .map(RoutingPolicyBundle::version).contains(StartupPolicyFixtures.VERSION);

            assertThat(afterCutover.getBean(RosterStore.class).current().entries())
                    .anySatisfy(entry -> assertThat(entry.homeserver().id()).isEqualTo(SEEDED_MEMBER));
        }
    }
}
