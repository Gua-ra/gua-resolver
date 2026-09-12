/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.JdbcTransparencyLog;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The placement state is anchored by a periodic checkpoint, never by a leaf per record.
 *
 * <p>The roster version is the transparency-log size and new-account fallback placement seeds on it
 * (ADM-001 L6 [CODE]), so one leaf per ingest would move placement decisions on every record. The checkpoint
 * appends at most one leaf per interval, and only when the Merkle root over the records actually changed,
 * which is the same idempotent-per-root rule the directory checkpoint follows.
 */
@SpringBootTest(properties = "gua.resolver.placement.enabled=true")
@DirtiesContext
class PlacementCheckpointTest {

    private static final Ed25519.KeyPairB64 KEY = Ed25519.generate();

    @DynamicPropertySource
    static void ownDatabase(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () ->
                "jdbc:h2:mem:placement-checkpoint;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
    }

    @Autowired JdbcPlacementRecordStore store;
    @Autowired PlacementCheckpointService service;
    @Autowired JdbcTransparencyLog transparencyLog;
    @Autowired ResolverProperties props;

    @Test
    void signsAndLogsOneLeafPerChangedRootAndNoneForAnEmptyState() {
        int loggedBefore = transparencyLog.eventsOfType(PlacementCheckpointService.EVENT_TYPE).size();

        // An empty placement state commits to nothing, so anchoring it would move fallback placement for
        // nothing.
        PlacementCheckpoint.Signed empty = service.publish();
        assertThat(empty.checkpoint().size()).isZero();
        assertThat(transparencyLog.eventsOfType(PlacementCheckpointService.EVENT_TYPE))
                .hasSize(loggedBefore);

        store.insert(record("checkpoint-a"));
        PlacementCheckpoint.Signed signed = service.publish();

        assertThat(signed.checkpoint().merkleRoot()).isNotBlank();
        assertThat(signed.checkpoint().size()).isEqualTo(1);
        assertThat(signed.signatures()).isNotEmpty();
        ResolverProperties.TrustedKey authorityKey = props.getAuthority().getTrustedKeys().get(0);
        assertThat(Ed25519.verify(Ed25519.publicKey(authorityKey.getPublicKey()),
                PlacementCheckpointService.canonicalBytes(signed.checkpoint()),
                signed.signatures().get(0).signatureB64())).isTrue();
        int afterFirst = transparencyLog.eventsOfType(PlacementCheckpointService.EVENT_TYPE).size();
        assertThat(afterFirst).isEqualTo(loggedBefore + 1);

        // Re-publishing an unchanged state appends nothing: idempotent per root.
        service.publish();
        service.publish();
        assertThat(transparencyLog.eventsOfType(PlacementCheckpointService.EVENT_TYPE))
                .hasSize(afterFirst);

        // A new record changes the root, and that is what earns exactly one more leaf.
        String rootBefore = signed.checkpoint().merkleRoot();
        store.insert(record("checkpoint-b"));
        PlacementCheckpoint.Signed next = service.publish();
        assertThat(next.checkpoint().merkleRoot()).isNotEqualTo(rootBefore);
        assertThat(next.checkpoint().size()).isEqualTo(2);
        assertThat(transparencyLog.eventsOfType(PlacementCheckpointService.EVENT_TYPE))
                .hasSize(afterFirst + 1);
    }

    @Test
    void theRootDependsOnlyOnTheRecordsAndNotOnWhenItWasComputed() {
        store.insert(record("checkpoint-stable"));

        assertThat(store.checkpoint().merkleRoot()).isEqualTo(store.checkpoint().merkleRoot());
    }

    private StoredPlacementRecord record(String seed) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        String accountId = PlacementFixtures.genesisAccountId(seed);
        byte[] canonical = PlacementFixtures.canonical(accountId, "dev", now);
        return new StoredPlacementRecord(accountId, "dev", 1, PlacementRecord.Origin.GENESIS,
                now, now, now.plus(PlacementFixtures.VALIDITY),
                PlacementFixtures.recordB64(canonical), PlacementFixtures.sign(canonical, KEY), now);
    }
}
