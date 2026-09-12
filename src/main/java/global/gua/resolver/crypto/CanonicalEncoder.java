package global.gua.resolver.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;

/**
 * The {@code gua-lp.v1} length-prefixed canonical encoding (ADM-007). Every signed object built on it has
 * exactly one byte representation, so a signature or hash over those bytes means one thing (ADM-001 L4).
 *
 * <ul>
 *   <li>byte string: u32 big-endian length, then the bytes;</li>
 *   <li>string: the byte string of its exact UTF-8 bytes, no normalization; a string that is not valid
 *       Unicode (an unpaired surrogate) is rejected rather than replaced;</li>
 *   <li>int64: 8 bytes big-endian two's complement; timestamps are epoch milliseconds;</li>
 *   <li>bool: one byte, 0x00 or 0x01;</li>
 *   <li>optional(T): a presence byte (0x00 absent, 0x01 present), then T when present, so absent and empty
 *       are different bytes;</li>
 *   <li>list(T): u32 count, then the elements in order; a set is a list sorted by unsigned UTF-8 byte order,
 *       and a duplicate is rejected;</li>
 *   <li>enum: its canonical name as a string.</li>
 * </ul>
 * An object starts with its schema tag as a string ({@link #begin}), then its fields in the documented order,
 * none omitted. Unlike {@code CanonicalRoster} there are no delimiters, so no value can be confused with
 * framing.
 */
public final class CanonicalEncoder {

    /** The encoding identifier, for documents that name the framing their objects use. */
    public static final String ENCODING = "gua-lp.v1";

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    private CanonicalEncoder() {}

    /** Start an object: the first field is always its schema tag (domain separation). */
    public static CanonicalEncoder begin(String schemaTag) {
        if (schemaTag == null || schemaTag.isEmpty()) {
            throw new CanonicalEncodingException("schema tag is required");
        }
        return new CanonicalEncoder().string(schemaTag);
    }

    /** An encoder with no schema tag, for encoding a bare primitive (test vectors, nested values). */
    public static CanonicalEncoder raw() {
        return new CanonicalEncoder();
    }

    public CanonicalEncoder bytes(byte[] value) {
        if (value == null) {
            throw new CanonicalEncodingException("byte string must not be null; use an optional field");
        }
        writeU32(value.length);
        out.writeBytes(value);
        return this;
    }

    public CanonicalEncoder string(String value) {
        if (value == null) {
            throw new CanonicalEncodingException("string must not be null; use an optional field");
        }
        return bytes(utf8(value));
    }

    public CanonicalEncoder int64(long value) {
        out.writeBytes(ByteBuffer.allocate(Long.BYTES).putLong(value).array());
        return this;
    }

    public CanonicalEncoder bool(boolean value) {
        out.write(value ? 1 : 0);
        return this;
    }

    /** optional(string): null is absent, and the empty string is present. */
    public CanonicalEncoder optionalString(String value) {
        if (value == null) {
            out.write(0);
            return this;
        }
        out.write(1);
        return string(value);
    }

    public <E extends Enum<E>> CanonicalEncoder enumName(E value) {
        if (value == null) {
            throw new CanonicalEncodingException("enum must not be null; use an optional field");
        }
        return string(value.name());
    }

    /** list(string) in the order given. */
    public CanonicalEncoder stringList(List<String> values) {
        if (values == null) {
            throw new CanonicalEncodingException("list must not be null");
        }
        writeU32(values.size());
        for (String v : values) {
            string(v);
        }
        return this;
    }

    /**
     * The {@code u32} element count that opens a list whose elements are composite rather than plain
     * strings. The caller then encodes each element's fields in order, so the framing is the same
     * {@code list(T)} rule: a count, then the elements. Used by the governance objects, whose lists hold
     * multi-field records (keys, registry members) instead of single values.
     */
    public CanonicalEncoder listCount(int count) {
        writeU32(count);
        return this;
    }

    /** A set of strings: sorted by unsigned UTF-8 byte order; a duplicate is an encoding error. */
    public CanonicalEncoder stringSet(Collection<String> values) {
        if (values == null) {
            throw new CanonicalEncodingException("set must not be null");
        }
        List<byte[]> encoded = new ArrayList<>(values.size());
        for (String v : values) {
            if (v == null) {
                throw new CanonicalEncodingException("set element must not be null");
            }
            encoded.add(utf8(v));
        }
        encoded.sort(Arrays::compareUnsigned);
        for (int i = 1; i < encoded.size(); i++) {
            if (Arrays.equals(encoded.get(i - 1), encoded.get(i))) {
                throw new CanonicalEncodingException(
                        "duplicate set element: " + new String(encoded.get(i), StandardCharsets.UTF_8));
            }
        }
        writeU32(encoded.size());
        for (byte[] e : encoded) {
            bytes(e);
        }
        return this;
    }

    public byte[] toByteArray() {
        return out.toByteArray();
    }

    /** SHA-256 over canonical bytes, as lowercase hex: the object hash every gua-lp.v1 object uses. */
    public static String sha256Hex(byte[] canonical) {
        return MerkleTree.sha256Hex(canonical);
    }

    /** Lowercase hex of arbitrary bytes, for test vectors and diagnostics. */
    public static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    private void writeU32(int length) {
        if (length < 0) {
            throw new CanonicalEncodingException("length out of range");
        }
        out.writeBytes(ByteBuffer.allocate(Integer.BYTES).putInt(length).array());
    }

    private static byte[] utf8(String value) {
        try {
            ByteBuffer buf = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value));
            byte[] bytes = new byte[buf.remaining()];
            buf.get(bytes);
            return bytes;
        } catch (CharacterCodingException e) {
            throw new CanonicalEncodingException("string is not valid Unicode (unpaired surrogate)");
        }
    }

    /** A value that has no canonical encoding: the object carrying it must be refused, never repaired. */
    public static class CanonicalEncodingException extends RuntimeException {
        public CanonicalEncodingException(String message) {
            super(message);
        }
    }
}
