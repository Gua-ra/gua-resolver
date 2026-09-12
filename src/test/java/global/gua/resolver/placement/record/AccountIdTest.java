/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An accountId has one canonical spelling (ADM-008 decision 2). These are the rules a decoder that accepted
 * eight spellings of one account would break, which ADM-001 L4 forbids.
 */
class AccountIdTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    void anIdIs58CharactersAndMatchesTheCanonicalPattern() {
        String id = PlacementFixtures.genesisAccountId("shape");

        assertThat(id).hasSize(AccountId.ENCODED_LENGTH).startsWith("ga1");
        assertThat(AccountId.CANONICAL.matcher(id).matches()).isTrue();
        assertThat(AccountId.isCanonical(id)).isTrue();
    }

    @Test
    void encodingAndDecodingRoundTrip() {
        byte[] raw = raw(AccountId.CLASS_GENESIS);

        String id = AccountId.encode(raw);

        assertThat(AccountId.decode(id)).containsExactly(raw);
        assertThat(AccountId.rootClass(AccountId.decode(id))).isEqualTo(AccountId.CLASS_GENESIS);
    }

    @Test
    void theLastCharacterOnlyEverCarriesThreeZeroPaddingBits() {
        // 34 bytes are 272 bits and 55 base32 characters carry 275, so the last character is one of four.
        for (int i = 0; i < 200; i++) {
            String id = AccountId.encode(raw(i % 2 == 0 ? AccountId.CLASS_GENESIS : AccountId.CLASS_BOOTSTRAP));
            assertThat(id.charAt(id.length() - 1)).isIn('a', 'i', 'q', 'y');
        }
    }

    @Test
    void aSpellingWithNonZeroPaddingBitsIsRefused() {
        String id = PlacementFixtures.genesisAccountId("padding");
        char last = id.charAt(id.length() - 1);
        // The next letter carries the same data bits with the padding set, so it is a second spelling of the
        // same 34 bytes: exactly the alias an accountId must not have.
        char aliased = (char) (last + 1);
        String alias = id.substring(0, id.length() - 1) + aliased;

        assertThat(AccountId.isCanonical(alias)).isFalse();
        assertThatThrownBy(() -> AccountId.decode(alias)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void malformedSpellingsAreRefused() {
        String id = PlacementFixtures.genesisAccountId("malformed");

        assertThat(AccountId.isCanonical(null)).isFalse();
        assertThat(AccountId.isCanonical("")).isFalse();
        assertThat(AccountId.isCanonical(id.toUpperCase(java.util.Locale.ROOT))).isFalse();
        assertThat(AccountId.isCanonical(id.substring(1))).isFalse();                    // no prefix
        assertThat(AccountId.isCanonical(id + "a")).isFalse();                           // too long
        assertThat(AccountId.isCanonical(id.substring(0, id.length() - 1))).isFalse();   // too short
        assertThat(AccountId.isCanonical("ga0" + id.substring(3))).isFalse();            // wrong prefix
        assertThat(AccountId.isCanonical(id.substring(0, 3) + "1" + id.substring(4))).isFalse();  // not base32
    }

    @Test
    void encodingRefusesAnythingThatIsNot34Bytes() {
        assertThatThrownBy(() -> AccountId.encode(new byte[33]))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AccountId.encode(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static byte[] raw(byte rootClass) {
        byte[] raw = new byte[AccountId.RAW_LENGTH];
        RANDOM.nextBytes(raw);
        raw[0] = AccountId.FORMAT_VERSION;
        raw[1] = rootClass;
        return raw;
    }
}
