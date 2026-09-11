package global.gua.resolver.crypto;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The gua-lp.v1 framing: injective where CanonicalRoster's delimiter form is not, absent distinct from empty,
 * sets in unsigned UTF-8 byte order with duplicates refused, fixed-width integers.
 */
class CanonicalEncoderTest {

    /** The byte CanonicalRoster joins entry fields with, assuming values never contain it (ADM-001 L4). */
    private static final String UNIT_SEPARATOR = Character.toString(0x1F);

    private static String hex(CanonicalEncoder e) {
        return CanonicalEncoder.hex(e.toByteArray());
    }

    @Test
    void stringsAreLengthPrefixedUtf8() {
        assertThat(hex(CanonicalEncoder.raw().string(""))).isEqualTo("00000000");
        assertThat(hex(CanonicalEncoder.raw().string("ab"))).isEqualTo("000000026162");
        // Two UTF-8 bytes for one character: the prefix counts bytes, not characters.
        assertThat(hex(CanonicalEncoder.raw().string("é"))).isEqualTo("00000002c3a9");
        assertThat(hex(CanonicalEncoder.raw().string("a" + UNIT_SEPARATOR + "b")))
                .isEqualTo("00000003611f62");
    }

    @Test
    void valuesContainingFormerDelimitersCannotShiftAFieldBoundary() {
        for (String d : List.of(UNIT_SEPARATOR, "|", "=", ";", ",", "\n", ":")) {
            byte[] left = CanonicalEncoder.begin("t.v1").string("x" + d + "y").string("z").toByteArray();
            byte[] right = CanonicalEncoder.begin("t.v1").string("x").string("y" + d + "z").toByteArray();
            assertThat(left).as("delimiter %s", d).isNotEqualTo(right);
        }
    }

    @Test
    void absentAndEmptyAreDifferentBytes() {
        assertThat(hex(CanonicalEncoder.raw().optionalString(null))).isEqualTo("00");
        assertThat(hex(CanonicalEncoder.raw().optionalString(""))).isEqualTo("0100000000");
        assertThat(hex(CanonicalEncoder.raw().optionalString("a"))).isEqualTo("010000000161");
    }

    @Test
    void setsSortByUnsignedUtf8BytesRegardlessOfInputOrder() {
        List<String> values = List.of("b", "a", "B", "é", "aa", "z");
        byte[] one = CanonicalEncoder.raw().stringSet(values).toByteArray();
        byte[] other = CanonicalEncoder.raw()
                .stringSet(List.of("z", "aa", "é", "B", "a", "b")).toByteArray();

        assertThat(one).isEqualTo(other);
        // B (0x42) < a < aa < b < z (0x7a) < e-acute (0xc3 0xa9), which a signed byte compare would sort first.
        assertThat(CanonicalEncoder.hex(one)).isEqualTo(
                "00000006" + "0000000142" + "0000000161" + "000000026161" + "0000000162" + "000000017a"
                        + "00000002c3a9");
    }

    @Test
    void aDuplicateSetElementIsRefused() {
        assertThatThrownBy(() -> CanonicalEncoder.raw().stringSet(List.of("edu", "edu")))
                .isInstanceOf(CanonicalEncoder.CanonicalEncodingException.class)
                .hasMessageContaining("duplicate");
    }

    @Test
    void listsKeepTheirOrderAndDifferFromTheSetEncoding() {
        assertThat(hex(CanonicalEncoder.raw().stringList(List.of("b", "a"))))
                .isEqualTo("00000002" + "0000000162" + "0000000161");
        assertThat(CanonicalEncoder.raw().stringList(List.of("b", "a")).toByteArray())
                .isNotEqualTo(CanonicalEncoder.raw().stringSet(List.of("b", "a")).toByteArray());
    }

    @Test
    void int64IsAlwaysEightBytesBigEndianTwosComplement() {
        assertThat(hex(CanonicalEncoder.raw().int64(0))).isEqualTo("0000000000000000");
        assertThat(hex(CanonicalEncoder.raw().int64(1))).isEqualTo("0000000000000001");
        assertThat(hex(CanonicalEncoder.raw().int64(-1))).isEqualTo("ffffffffffffffff");
        assertThat(hex(CanonicalEncoder.raw().int64(Long.MAX_VALUE))).isEqualTo("7fffffffffffffff");
        assertThat(hex(CanonicalEncoder.raw().int64(1_789_084_800_000L))).isEqualTo("000001a08dc39400");
    }

    @Test
    void boolAndEnumEncodings() {
        assertThat(hex(CanonicalEncoder.raw().bool(false))).isEqualTo("00");
        assertThat(hex(CanonicalEncoder.raw().bool(true))).isEqualTo("01");
        assertThat(hex(CanonicalEncoder.raw().enumName(Thread.State.NEW))).isEqualTo("000000034e4557");
    }

    @Test
    void theSchemaTagComesFirst() {
        assertThat(hex(CanonicalEncoder.begin("t.v1"))).isEqualTo("00000004742e7631");
        assertThatThrownBy(() -> CanonicalEncoder.begin(""))
                .isInstanceOf(CanonicalEncoder.CanonicalEncodingException.class);
    }

    @Test
    void stringsThatAreNotValidUnicodeAndNullsAreRefused() {
        assertThatThrownBy(() -> CanonicalEncoder.raw().string("a\ud800b"))
                .isInstanceOf(CanonicalEncoder.CanonicalEncodingException.class)
                .hasMessageContaining("surrogate");
        assertThatThrownBy(() -> CanonicalEncoder.raw().string(null))
                .isInstanceOf(CanonicalEncoder.CanonicalEncodingException.class);
        assertThatThrownBy(() -> CanonicalEncoder.raw().stringSet(Arrays.asList("a", null)))
                .isInstanceOf(CanonicalEncoder.CanonicalEncodingException.class);
    }

    @Test
    void theObjectHashIsLowercaseSha256Hex() {
        byte[] bytes = CanonicalEncoder.begin("t.v1").string("x").toByteArray();

        assertThat(CanonicalEncoder.sha256Hex(bytes)).matches("[0-9a-f]{64}");
    }
}
