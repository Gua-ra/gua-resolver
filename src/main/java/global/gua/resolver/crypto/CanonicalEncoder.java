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

public final class CanonicalEncoder {

    public static final String ENCODING = "gua-lp.v1";

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    private CanonicalEncoder() {}

    public static CanonicalEncoder begin(String schemaTag) {
        if (schemaTag == null || schemaTag.isEmpty()) {
            throw new CanonicalEncodingException("schema tag is required");
        }
        return new CanonicalEncoder().string(schemaTag);
    }

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

    /** null is absent; the empty string is present. */
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

    public CanonicalEncoder listCount(int count) {
        writeU32(count);
        return this;
    }

    /** Sorted by unsigned UTF-8 byte order; a duplicate is an encoding error. */
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

    public static String sha256Hex(byte[] canonical) {
        return MerkleTree.sha256Hex(canonical);
    }

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

    public static class CanonicalEncodingException extends RuntimeException {
        public CanonicalEncodingException(String message) {
            super(message);
        }
    }
}
