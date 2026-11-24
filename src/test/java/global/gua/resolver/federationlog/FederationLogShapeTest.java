package global.gua.resolver.federationlog;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import global.gua.resolver.crypto.CanonicalEncoder.CanonicalEncodingException;

import static global.gua.resolver.federationlog.LogEntry.Type.GENESIS;
import static global.gua.resolver.federationlog.LogEntry.Type.MEMBER_ENTRY;
import static global.gua.resolver.federationlog.LogEntry.Type.REGISTRY_EPOCH;
import static global.gua.resolver.federationlog.LogEntry.Type.TIME;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FederationLogShapeTest {

    private static final String GENESIS_ID = "a".repeat(64);
    private static final String OBJECT_HASH = "b".repeat(64);
    private static final Instant AT = Instant.parse("2026-11-01T00:00:00Z");
    private static final String SIGNATURE = Base64.getEncoder().encodeToString(new byte[64]);

    private static LogEntry entry(long index, LogEntry.Type type, String objectHash, String... signers) {
        List<KeySignature> signatures = Stream.of(signers).map(id -> new KeySignature(id, SIGNATURE)).toList();
        return new LogEntry(LogEntry.SCHEMA, GENESIS_ID, index, AT, type, objectHash, signatures);
    }

    @Test
    void entryZeroIsTheGenesisAndNamesItself() {
        assertThatCode(() -> entry(0, GENESIS, GENESIS_ID, "gov-1").validateShape()).doesNotThrowAnyException();
        assertThatThrownBy(() -> entry(0, GENESIS, OBJECT_HASH, "gov-1").validateShape())
                .isInstanceOf(FederationLogException.class);
        assertThatThrownBy(() -> entry(1, GENESIS, GENESIS_ID, "gov-1").validateShape())
                .isInstanceOf(FederationLogException.class);
        assertThatThrownBy(() -> entry(0, REGISTRY_EPOCH, OBJECT_HASH, "gov-1").validateShape())
                .isInstanceOf(FederationLogException.class);
    }

    @Test
    void aTimeEntryNamesNoObjectAndEveryOtherEntryIsSigned() {
        assertThatCode(() -> entry(3, TIME, null).validateShape()).doesNotThrowAnyException();
        assertThatThrownBy(() -> entry(3, TIME, OBJECT_HASH).validateShape())
                .isInstanceOf(FederationLogException.class);
        assertThatThrownBy(() -> entry(3, TIME, null, "gov-1").validateShape())
                .isInstanceOf(FederationLogException.class);
        assertThatThrownBy(() -> entry(3, MEMBER_ENTRY, OBJECT_HASH).validateShape())
                .isInstanceOf(FederationLogException.class);
        assertThatThrownBy(() -> entry(3, MEMBER_ENTRY, null, "hs1").validateShape())
                .isInstanceOf(FederationLogException.class);
    }

    @Test
    void timesAreWholeMillisecondsAndHashesAreLowercaseHex() {
        LogEntry subMillisecond = new LogEntry(LogEntry.SCHEMA, GENESIS_ID, 3, AT.plusNanos(1), TIME, null, null);
        assertThatThrownBy(subMillisecond::validateShape).isInstanceOf(FederationLogException.class);
        assertThatThrownBy(() -> entry(3, MEMBER_ENTRY, OBJECT_HASH.toUpperCase(), "hs1").validateShape())
                .isInstanceOf(FederationLogException.class);
        assertThatThrownBy(() -> new Checkpoint(Checkpoint.SCHEMA, GENESIS_ID, 1, OBJECT_HASH, "abc", AT, null)
                .validateShape()).isInstanceOf(FederationLogException.class);
    }

    @Test
    void aCheckpointCoversAtLeastTheGenesisEntry() {
        assertThatThrownBy(() -> new Checkpoint(Checkpoint.SCHEMA, GENESIS_ID, 0, OBJECT_HASH, OBJECT_HASH, AT,
                null).validateShape()).isInstanceOf(FederationLogException.class);
    }

    @Test
    void theStateNamesEachHomeserverOnce() {
        FederationState.MemberEntry hs1 = new FederationState.MemberEntry("hs1", OBJECT_HASH);
        FederationState twice = new FederationState(FederationState.SCHEMA, GENESIS_ID, GENESIS_ID, null,
                List.of(hs1, hs1), null);
        assertThatThrownBy(twice::canonicalBytes).isInstanceOf(CanonicalEncodingException.class);
        FederationState badHash = new FederationState(FederationState.SCHEMA, GENESIS_ID, GENESIS_ID, null,
                List.of(new FederationState.MemberEntry("hs1", "abc")), null);
        assertThatThrownBy(badHash::validateShape).isInstanceOf(FederationLogException.class);
    }

    @Test
    void aDuplicateOrMalformedSignatureHasNoCanonicalEncoding() {
        assertThatThrownBy(() -> entry(3, MEMBER_ENTRY, OBJECT_HASH, "hs1", "hs1").canonicalBytes())
                .isInstanceOf(CanonicalEncodingException.class);
        String shortSignature = Base64.getEncoder().encodeToString(new byte[63]);
        assertThatThrownBy(() -> new LogEntry(LogEntry.SCHEMA, GENESIS_ID, 3, AT, MEMBER_ENTRY, OBJECT_HASH,
                List.of(new KeySignature("hs1", shortSignature))).canonicalBytes())
                .isInstanceOf(CanonicalEncodingException.class);
        assertThatThrownBy(() -> new LogEntry(LogEntry.SCHEMA, GENESIS_ID, 3, AT, MEMBER_ENTRY, OBJECT_HASH,
                List.of(new KeySignature("hs1", "not base64!"))).canonicalBytes())
                .isInstanceOf(CanonicalEncodingException.class);
    }
}
