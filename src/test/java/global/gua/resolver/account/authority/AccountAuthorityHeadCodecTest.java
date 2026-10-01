/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import global.gua.resolver.placement.record.AccountId;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The head object's wire format: one reading per byte string, one rejection reason per defect, and no repairs.
 *
 * <p>The decode is what a forged head has to get past, so each test below is a way of lying about a head and
 * the reason it is refused for. The round trip is asserted on the bytes rather than on the decoded fields,
 * because the bytes are what the signature covers and what the log leaf commits to.
 */
class AccountAuthorityHeadCodecTest {

    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.MILLIS);
    private static final String ACCOUNT = AuthorityHeadFixtures.bootstrapAccountId("codec");
    private static final String HEAD = AuthorityHeadFixtures.headHash("codec-head");

    private static byte[] valid() {
        return AuthorityHeadFixtures.canonical(ACCOUNT, HEAD, 7, "hs-one", NOW);
    }

    @Test
    void aWellFormedHeadRoundTrips() {
        byte[] canonical = valid();
        assertThat(canonical).hasSize(AccountAuthorityHeadCodec.FIXED_LENGTH + "hs-one".length());

        AccountAuthorityHead head = AccountAuthorityHeadCodec.decode(canonical);
        assertThat(head.version()).isEqualTo(AccountAuthorityHeadCodec.VERSION);
        assertThat(head.suite()).isEqualTo(AccountAuthorityHeadCodec.SUITE);
        assertThat(head.accountId()).isEqualTo(ACCOUNT);
        assertThat(head.headHashHex()).isEqualTo(HEAD);
        assertThat(head.headSeq()).isEqualTo(7);
        assertThat(head.homeserverId()).isEqualTo("hs-one");
        assertThat(head.issuedAt()).isEqualTo(NOW);
        assertThat(head.notAfter()).isEqualTo(NOW.plus(AuthorityHeadFixtures.VALIDITY));
        assertThat(AccountAuthorityHeadCodec.encode(head)).isEqualTo(canonical);
    }

    @Test
    void theAccountIdIsReDerivedFromTheBytesRatherThanTakenFromACaller() {
        // The 34 raw bytes in the object are the only source of the storage key, so the id in the decoded view
        // is always the one canonical spelling of what the signature covered.
        AccountAuthorityHead head = AccountAuthorityHeadCodec.decode(valid());
        assertThat(AccountId.isCanonical(head.accountId())).isTrue();
        assertThat(head.accountId()).hasSize(AccountId.ENCODED_LENGTH);
    }

    @Test
    void theMagicIsDistinctFromEveryOtherObjectARosterKeySigns() {
        assertThat(new String(AccountAuthorityHeadCodec.MAGIC,
                java.nio.charset.StandardCharsets.US_ASCII)).isEqualTo("GUAH");
        byte[] wrongMagic = valid();
        wrongMagic[3] = 'P';   // "GUAP", the placement record
        refused(wrongMagic, AccountAuthorityHeadRejection.BAD_MAGIC);
    }

    @Test
    void anUnknownVersionOrSuiteIsRefusedRatherThanGuessed() {
        byte[] version = valid();
        version[4] = 0x02;
        refused(version, AccountAuthorityHeadRejection.UNSUPPORTED_VERSION);

        byte[] suite = valid();
        suite[5] = 0x02;   // the reserved hardware-resident suite, which this build does not decode
        refused(suite, AccountAuthorityHeadRejection.UNSUPPORTED_SUITE);
    }

    @Test
    void anAccountIdWithAnUnknownVersionOrClassIsRefused() {
        byte[] idVersion = valid();
        idVersion[6] = 0x02;
        refused(idVersion, AccountAuthorityHeadRejection.BAD_ACCOUNT_ID_VERSION);

        byte[] idClass = valid();
        idClass[7] = 0x07;
        refused(idClass, AccountAuthorityHeadRejection.UNKNOWN_ACCOUNT_CLASS);
    }

    @Test
    void anEmptyChainCannotBePublishedAsAHead() {
        // 32 zero bytes is the first record's prevHash, which names no record at all.
        byte[] zeroHead = valid();
        Arrays.fill(zeroHead, 40, 72, (byte) 0);
        refused(zeroHead, AccountAuthorityHeadRejection.ZERO_HEAD_HASH);
    }

    @Test
    void aSequenceNumberBelowTheFirstRecordIsRefused() {
        byte[] zeroSeq = valid();
        Arrays.fill(zeroSeq, 72, 80, (byte) 0);
        refused(zeroSeq, AccountAuthorityHeadRejection.BAD_HEAD_SEQ);

        // The high bit set reads as negative as a signed long: past every sequence a chain can reach.
        byte[] huge = valid();
        huge[72] = (byte) 0x80;
        refused(huge, AccountAuthorityHeadRejection.BAD_HEAD_SEQ);
    }

    @Test
    void theHomeserverIdLengthMustDescribeTheBytesThatFollow() {
        byte[] zeroLength = valid();
        zeroLength[80] = 0;
        refused(zeroLength, AccountAuthorityHeadRejection.BAD_HOMESERVER_ID_LENGTH);

        byte[] wrongLength = valid();
        wrongLength[80] = 5;   // declares five characters in a six-character id
        refused(wrongLength, AccountAuthorityHeadRejection.DECLARED_LENGTH_MISMATCH);

        // One byte short of what the prefix declares: truncation is a length mismatch, not a shorter id.
        byte[] longId = AuthorityHeadFixtures.canonical(ACCOUNT, HEAD, 7, "hs-one-long", NOW);
        refused(Arrays.copyOfRange(longId, 0, longId.length - 1),
                AccountAuthorityHeadRejection.DECLARED_LENGTH_MISMATCH);
    }

    @Test
    void aHomeserverIdCarryingTheLeafDelimiterIsRefused() {
        // The transparency-log leaf is delimited on '|', so an id containing one would give a leaf string two
        // readings, and a second reading is a second leaf preimage a verifier could be steered to.
        byte[] delimiter = valid();
        delimiter[81] = '|';
        refused(delimiter, AccountAuthorityHeadRejection.INVALID_HOMESERVER_ID);

        byte[] nonPrintable = valid();
        nonPrintable[81] = 0x0A;
        refused(nonPrintable, AccountAuthorityHeadRejection.INVALID_HOMESERVER_ID);
    }

    @Test
    void anUnorderedOrUnrepresentableWindowIsRefused() {
        Instant issued = NOW;
        AccountAuthorityHead backwards = new AccountAuthorityHead(
                AccountAuthorityHeadCodec.VERSION, AccountAuthorityHeadCodec.SUITE, ACCOUNT, HEAD, 3,
                "hs-one", issued, issued.plusSeconds(60), issued.plusSeconds(60));
        refused(AccountAuthorityHeadCodec.encode(backwards),
                AccountAuthorityHeadRejection.WINDOW_NOT_ORDERED);

        byte[] outOfRange = valid();
        int offset = 81 + "hs-one".length();
        outOfRange[offset] = (byte) 0x80;   // issuedAt with the high bit set
        refused(outOfRange, AccountAuthorityHeadRejection.TIMESTAMP_OUT_OF_RANGE);
    }

    @Test
    void anythingOutsideThePossibleLengthRangeIsRefusedBeforeAnyFieldIsRead() {
        refused(null, AccountAuthorityHeadRejection.WRONG_LENGTH);
        refused(new byte[0], AccountAuthorityHeadRejection.WRONG_LENGTH);
        refused(new byte[AccountAuthorityHeadCodec.FIXED_LENGTH],
                AccountAuthorityHeadRejection.WRONG_LENGTH);
        refused(new byte[AccountAuthorityHeadCodec.FIXED_LENGTH
                        + AccountAuthorityHeadCodec.MAX_HOMESERVER_ID_LENGTH + 1],
                AccountAuthorityHeadRejection.WRONG_LENGTH);
    }

    private static void refused(byte[] canonical, AccountAuthorityHeadRejection expected) {
        assertThatThrownBy(() -> AccountAuthorityHeadCodec.decode(canonical))
                .isInstanceOf(AccountAuthorityHeadException.class)
                .extracting(e -> ((AccountAuthorityHeadException) e).rejection())
                .isEqualTo(expected);
    }
}
