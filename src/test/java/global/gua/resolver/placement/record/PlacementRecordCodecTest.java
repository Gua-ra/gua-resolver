/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import global.gua.resolver.api.PlacementRecordController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * The fixed-layout decode (ADM-008 encoding tables). Every malformed case is refused, each with its own
 * reason, and none is repaired. The decode is pure, so nothing here needs a clock, a roster or a database:
 * that separation is what lets the public ingest answer a structural failure without touching stored state.
 */
class PlacementRecordCodecTest {

    private static final String HOMESERVER = "hs-one";
    private static final Instant ISSUED = Instant.parse("2026-09-11T12:00:00Z");

    @Test
    void aWellFormedRecordDecodesAndRederivesTheAccountIdFromItsRawBytes() {
        String accountId = PlacementFixtures.genesisAccountId("codec-ok");
        byte[] canonical = PlacementFixtures.canonical(accountId, HOMESERVER, ISSUED);

        PlacementRecord decoded = PlacementRecordCodec.decode(canonical);

        assertThat(decoded.version()).isEqualTo(1);
        assertThat(decoded.generation()).isEqualTo(1);
        assertThat(decoded.accountId()).isEqualTo(accountId);
        assertThat(decoded.origin()).isEqualTo(PlacementRecord.Origin.GENESIS);
        assertThat(decoded.homeserverId()).isEqualTo(HOMESERVER);
        assertThat(decoded.issuedAt()).isEqualTo(ISSUED);
        assertThat(decoded.notBefore()).isEqualTo(ISSUED);
        assertThat(decoded.notAfter()).isEqualTo(ISSUED.plus(PlacementFixtures.VALIDITY));
        // The bytes are exactly 66 + the homeserver-id length, and re-encoding reproduces them.
        assertThat(canonical).hasSize(PlacementRecordCodec.FIXED_LENGTH + HOMESERVER.length());
        assertThat(PlacementRecordCodec.encode(decoded)).containsExactly(canonical);
    }

    @Test
    void aBootstrapRecordDecodesWithItsOwnOrigin() {
        String accountId = PlacementFixtures.bootstrapAccountId("codec-bootstrap");

        PlacementRecord decoded = PlacementRecordCodec.decode(
                PlacementFixtures.canonical(accountId, HOMESERVER, ISSUED));

        assertThat(decoded.origin()).isEqualTo(PlacementRecord.Origin.BOOTSTRAP);
    }

    @Test
    void aRecordCarriesNoIdentifier() {
        // The whole object is 66 + n bytes of magic, version, generation, an account hash, an origin byte, a
        // roster id and three timestamps. There is no field a phone, a phone hash or a Matrix user id could
        // be carried in (ADM-001 L4, L15), and this is the test that fails if one is ever added.
        String accountId = PlacementFixtures.genesisAccountId("codec-fields");
        byte[] canonical = PlacementFixtures.canonical(accountId, HOMESERVER, ISSUED);

        assertThat(canonical).hasSize(PlacementRecordCodec.FIXED_LENGTH + HOMESERVER.length());
        assertThat(PlacementRecord.class.getRecordComponents())
                .extracting(java.lang.reflect.RecordComponent::getName)
                .containsExactly("version", "generation", "accountId", "origin", "homeserverId",
                        "issuedAt", "notBefore", "notAfter");
    }

    @Test
    void neitherTheStoredRowNorTheApiResponseCarriesAnIdentifier() {
        // The decoded record is pinned above. These are the shapes it turns into afterwards, pinned for the
        // same reason and against the same rule: no identifier of any kind in per-account federation state,
        // held or served (ADM-001 L4, L15). The database columns are pinned in PlacementRecordIngestTest,
        // where there is a schema to read.
        assertThat(StoredPlacementRecord.class.getRecordComponents())
                .extracting(java.lang.reflect.RecordComponent::getName)
                .containsExactly("accountId", "homeserverId", "generation", "origin", "issuedAt",
                        "notBefore", "notAfter", "recordB64", "signatureB64", "receivedAt");
        assertThat(PlacementRecordController.PageItem.class.getRecordComponents())
                .extracting(java.lang.reflect.RecordComponent::getName)
                .containsExactly("accountId", "homeserverId", "origin", "record", "signature");
        assertThat(PlacementRecordEnvelope.class.getRecordComponents())
                .extracting(java.lang.reflect.RecordComponent::getName)
                .containsExactly("record", "signature");
    }

    @Test
    void everyMalformedCaseIsRefusedWithItsOwnReason() {
        String accountId = PlacementFixtures.genesisAccountId("codec-bad");
        byte[] valid = PlacementFixtures.canonical(accountId, HOMESERVER, ISSUED);
        int timestamps = 42 + HOMESERVER.length();

        List<PlacementRecordRejection> seen = new ArrayList<>();
        seen.add(reasonFor(Arrays.copyOf(valid, 40)));                               // not a record at all
        seen.add(reasonFor(mutate(valid, b -> b[0] = 'X')));                         // magic
        seen.add(reasonFor(mutate(valid, b -> b[4] = 0x02)));                        // version
        seen.add(reasonFor(mutate(valid, b -> b[5] = 0x02)));                        // generation
        seen.add(reasonFor(mutate(valid, b -> b[6] = 0x02)));                        // accountId version
        seen.add(reasonFor(mutate(valid, b -> b[7] = 0x07)));                        // accountId class
        seen.add(reasonFor(mutate(valid, b -> b[40] = 0x07)));                       // origin byte
        seen.add(reasonFor(mutate(valid, b -> b[40] = 0x00)));                       // origin vs class
        seen.add(reasonFor(mutate(valid, b -> b[41] = 0x00)));                       // declared length 0
        seen.add(reasonFor(mutate(valid, b -> b[41] = (byte) (HOMESERVER.length() + 1))));
        seen.add(reasonFor(mutate(valid, b -> b[42] = 0x00)));                       // homeserver id byte
        seen.add(reasonFor(mutate(valid, b -> b[timestamps] = (byte) 0xFF)));        // issuedAt out of range
        seen.add(reasonFor(mutate(valid, b -> {                                      // notAfter <= notBefore
            System.arraycopy(b, timestamps + 8, b, timestamps + 16, 8);
        })));

        assertThat(seen).containsExactly(
                PlacementRecordRejection.WRONG_LENGTH,
                PlacementRecordRejection.BAD_MAGIC,
                PlacementRecordRejection.UNSUPPORTED_VERSION,
                PlacementRecordRejection.UNSUPPORTED_GENERATION,
                PlacementRecordRejection.BAD_ACCOUNT_ID_VERSION,
                PlacementRecordRejection.UNKNOWN_ACCOUNT_CLASS,
                PlacementRecordRejection.UNKNOWN_ORIGIN,
                PlacementRecordRejection.ORIGIN_CLASS_MISMATCH,
                PlacementRecordRejection.BAD_HOMESERVER_ID_LENGTH,
                PlacementRecordRejection.DECLARED_LENGTH_MISMATCH,
                PlacementRecordRejection.INVALID_HOMESERVER_ID,
                PlacementRecordRejection.TIMESTAMP_OUT_OF_RANGE,
                PlacementRecordRejection.WINDOW_NOT_ORDERED);
        // One reason per defect, not one catch-all: an operator can tell a bad signer from a bad build.
        assertThat(seen).doesNotHaveDuplicates();
    }

    @Test
    void theTwoWaysALengthCanBeWrongAreToldApart() {
        byte[] valid = PlacementFixtures.canonical(
                PlacementFixtures.genesisAccountId("codec-lengths"), HOMESERVER, ISSUED);

        // One byte short of what the length prefix declares: the body is truncated, not simply the wrong
        // size, and the prefix is what says so.
        assertThat(reasonFor(Arrays.copyOf(valid, valid.length - 1)))
                .isEqualTo(PlacementRecordRejection.DECLARED_LENGTH_MISMATCH);
        // A trailing byte nobody declared, which is the same defect from the other side.
        assertThat(reasonFor(Arrays.copyOf(valid, valid.length + 1)))
                .isEqualTo(PlacementRecordRejection.DECLARED_LENGTH_MISMATCH);
        // A declared homeserver-id length above the maximum the layout allows.
        assertThat(reasonFor(mutate(valid, b -> b[41] = 0x41)))
                .isEqualTo(PlacementRecordRejection.BAD_HOMESERVER_ID_LENGTH);
    }

    @Test
    void theCheckpointDelimiterCannotAppearInsideAHomeserverId() {
        // The transparency-log leaves are A|<accountId>|<homeserverId>|<origin>, and the accountId is fixed
        // length, so refusing the delimiter here is what leaves one leaf string with one reading.
        byte[] valid = PlacementFixtures.canonical(
                PlacementFixtures.genesisAccountId("codec-delimiter"), HOMESERVER, ISSUED);

        assertThat(reasonFor(mutate(valid, b -> b[42] = '|')))
                .isEqualTo(PlacementRecordRejection.INVALID_HOMESERVER_ID);
    }

    @Test
    void nothingAtAllIsRefusedAsALengthProblem() {
        assertThat(reasonFor(null)).isEqualTo(PlacementRecordRejection.WRONG_LENGTH);
        assertThat(reasonFor(new byte[0])).isEqualTo(PlacementRecordRejection.WRONG_LENGTH);
        assertThat(reasonFor(new byte[200])).isEqualTo(PlacementRecordRejection.WRONG_LENGTH);
    }

    @Test
    void encodingRefusesAHomeserverIdThatCannotFitTheLengthPrefix() {
        PlacementRecord tooLong = PlacementFixtures.record(
                PlacementFixtures.genesisAccountId("codec-long"), "x".repeat(65), ISSUED);

        assertThatThrownBy(() -> PlacementRecordCodec.encode(tooLong))
                .isInstanceOf(PlacementRecordException.class);
    }

    private static PlacementRecordRejection reasonFor(byte[] canonical) {
        PlacementRecordException e = catchThrowableOfType(PlacementRecordException.class,
                () -> PlacementRecordCodec.decode(canonical));
        assertThat(e).as("expected a refusal").isNotNull();
        return e.rejection();
    }

    private static byte[] mutate(byte[] canonical, Consumer<byte[]> change) {
        byte[] copy = Arrays.copyOf(canonical, canonical.length);
        change.accept(copy);
        return copy;
    }
}
