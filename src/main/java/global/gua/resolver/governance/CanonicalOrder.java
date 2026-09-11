package global.gua.resolver.governance;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.function.Function;

import global.gua.resolver.crypto.CanonicalEncoder;

/**
 * The ordering rule the {@code gua-lp.v1} set encoding uses, applied to lists whose elements are records
 * rather than bare strings: sort by one field's unsigned UTF-8 byte order and refuse a duplicate. Sorting
 * makes the bytes independent of the order a list arrived in; refusing duplicates keeps two elements from
 * naming the same thing, which is what would let one operator's key or one homeserver appear twice and be
 * counted twice.
 */
final class CanonicalOrder {

    private CanonicalOrder() {}

    /** {@code values} sorted by {@code key}, with a duplicate key refused as an encoding error. */
    static <T> List<T> sortedUnique(Collection<T> values, Function<T, String> key, String what) {
        if (values == null) {
            throw new CanonicalEncoder.CanonicalEncodingException(what + " list must not be null");
        }
        List<T> sorted = new ArrayList<>(values);
        for (T value : sorted) {
            if (value == null || key.apply(value) == null) {
                throw new CanonicalEncoder.CanonicalEncodingException(what + " element has no key");
            }
        }
        sorted.sort(Comparator.comparing(v -> utf8(key.apply(v)), Arrays::compareUnsigned));
        for (int i = 1; i < sorted.size(); i++) {
            if (key.apply(sorted.get(i - 1)).equals(key.apply(sorted.get(i)))) {
                throw new CanonicalEncoder.CanonicalEncodingException(
                        "duplicate " + what + ": " + key.apply(sorted.get(i)));
            }
        }
        return sorted;
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
