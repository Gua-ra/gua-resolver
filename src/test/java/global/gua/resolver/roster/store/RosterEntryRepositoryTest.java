package global.gua.resolver.roster.store;

import java.time.Instant;
import java.util.List;
import java.util.TimeZone;

import javax.sql.DataSource;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.CanonicalMemberEntry;
import global.gua.resolver.roster.MemberAttestation;
import global.gua.resolver.roster.MemberEntrySigner;
import global.gua.resolver.roster.MemberSignature;
import global.gua.resolver.roster.RosterEntry;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The attestation columns round-trip through H2 exactly, including across a daylight-saving fold: the
 * validity window is signed, so a timestamp that comes back an hour out would silently invalidate every
 * member signature the resolver serves.
 */
class RosterEntryRepositoryTest {

    private static final Ed25519.KeyPairB64 KEY = Ed25519.generate();

    private final TimeZone original = TimeZone.getDefault();
    private RosterEntryRepository repository;
    private JdbcTemplate jdbc;

    @BeforeEach
    void setUp() {
        DataSource ds = new SimpleDriverDataSource(new org.h2.Driver(),
                "jdbc:h2:mem:repo-" + System.nanoTime() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        new ResourceDatabasePopulator(new ClassPathResource("schema.sql")).execute(ds);
        jdbc = new JdbcTemplate(ds);
        repository = new RosterEntryRepository(jdbc, new ObjectMapper().findAndRegisterModules());
    }

    @AfterEach
    void tearDown() {
        TimeZone.setDefault(original);
    }

    private static Homeserver homeserver(String signingKey) {
        return new Homeserver("hs1", "hs1.gua.test", "https://matrix.hs1.gua.test",
                "https://account.hs1.gua.test/", "BR", 1, true, signingKey,
                Homeserver.SearchVisibility.GROUP, List.of("edu-br"));
    }

    private static MemberAttestation attestation(Homeserver hs, long sequence, Instant notBefore) {
        MemberAttestation unsigned = new MemberAttestation(CanonicalMemberEntry.SCHEMA,
                CanonicalMemberEntry.ALG, "k1", sequence, notBefore, notBefore.plusSeconds(86_400),
                List.of());
        return MemberEntrySigner.sign(hs, unsigned, "k1", KEY.privateKeyB64());
    }

    @Test
    void anUnattestedEntryStaysLegalAndReadsBackWithNoMemberBlock() {
        repository.insert(new RosterEntry(homeserver(""), List.of(), Instant.now(),
                RosterEntry.Status.ACTIVE));

        RosterEntry read = repository.findById("hs1").orElseThrow();

        assertThat(read.member()).isNull();
        assertThat(repository.memberEntryHash("hs1")).isEmpty();
    }

    @Test
    void anAttestedEntryRoundTripsWithTheBytesItsSignatureCovers() {
        Homeserver hs = homeserver(KEY.publicKeyB64());
        Instant notBefore = Instant.parse("2026-09-11T00:00:00.250Z");
        MemberAttestation member = attestation(hs, 1, notBefore);
        String hash = CanonicalMemberEntry.hash(hs, member);

        repository.insert(new RosterEntry(hs, List.of(), Instant.now(), RosterEntry.Status.ACTIVE, member),
                hs.signingKey(), null, hash);

        RosterEntry read = repository.findById("hs1").orElseThrow();
        assertThat(read.member()).isEqualTo(member);
        assertThat(CanonicalMemberEntry.hash(read.homeserver(), read.member())).isEqualTo(hash);
        assertThat(repository.memberEntryHash("hs1")).contains(hash);
        assertThat(jdbc.queryForObject("SELECT genesis_signing_key FROM roster_entry WHERE id = 'hs1'",
                String.class)).isEqualTo(hs.signingKey());
    }

    @Test
    void theSignedValidityWindowSurvivesADaylightSavingFold() {
        TimeZone.setDefault(TimeZone.getTimeZone("America/New_York"));
        Homeserver hs = homeserver(KEY.publicKeyB64());
        // 01:30 local on the night the clocks go back: one local time, two instants.
        Instant ambiguous = Instant.parse("2026-11-01T05:30:00Z");
        MemberAttestation member = attestation(hs, 1, ambiguous);
        String hash = CanonicalMemberEntry.hash(hs, member);

        repository.insert(new RosterEntry(hs, List.of(), Instant.now(), RosterEntry.Status.ACTIVE, member),
                hs.signingKey(), null, hash);
        RosterEntry read = repository.findById("hs1").orElseThrow();

        assertThat(read.member().notBefore()).isEqualTo(ambiguous);
        assertThat(CanonicalMemberEntry.hash(read.homeserver(), read.member())).isEqualTo(hash);
    }

    @Test
    void updateMemberReplacesOnlyTheMemberControlledFieldsAndTheHistoryKeepsTheChain() {
        Homeserver admitted = new Homeserver("hs1", "hs1.gua.test", "https://old.hs1.gua.test",
                "https://account.hs1.gua.test/", "BR", 7, false, KEY.publicKeyB64(),
                Homeserver.SearchVisibility.GLOBAL, List.of());
        repository.insert(new RosterEntry(admitted, List.of(), Instant.now(), RosterEntry.Status.ACTIVE));

        Homeserver attested = homeserver(KEY.publicKeyB64());   // moved baseUrl, GROUP visibility
        MemberAttestation member = attestation(attested, 4, Instant.parse("2026-09-11T00:00:00Z"));
        String hash = CanonicalMemberEntry.hash(attested, member);
        repository.updateMember("hs1", attested, member, hash);
        repository.insertMemberHistory("hs1", member, attested.signingKey(), "{}", hash,
                Instant.parse("2026-09-11T10:00:00.123Z"), 42L);

        RosterEntry read = repository.findById("hs1").orElseThrow();
        assertThat(read.homeserver().baseUrl()).isEqualTo("https://matrix.hs1.gua.test");
        assertThat(read.homeserver().searchGroups()).containsExactly("edu-br");
        // The authority keeps these: a member cannot vote itself more placement weight.
        assertThat(read.homeserver().weight()).isEqualTo(7);
        assertThat(read.homeserver().acceptsNew()).isFalse();
        assertThat(read.member().sequence()).isEqualTo(4);

        List<RosterEntryRepository.MemberHistoryRow> history = repository.memberHistory("hs1");
        assertThat(history).singleElement().satisfies(row -> {
            assertThat(row.sequence()).isEqualTo(4);
            assertThat(row.keyId()).isEqualTo("k1");
            assertThat(row.entryHash()).isEqualTo(hash);
            assertThat(row.acceptedAt()).isEqualTo(Instant.parse("2026-09-11T10:00:00.123Z"));
            assertThat(row.logLeafIndex()).isEqualTo(42L);
            assertThat(row.signatures()).extracting(MemberSignature::keyId).containsExactly("k1");
        });
    }
}
