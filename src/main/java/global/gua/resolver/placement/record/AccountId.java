/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.util.regex.Pattern;

/**
 * The account identifier string and its one canonical spelling (ADM-008 decision 2).
 *
 * <p>{@code accountId = "ga1" || base32(0x01 || class || SHA-256(canonical genesis bytes))}, where base32 is
 * RFC 4648, lowercase and unpadded. The 34 raw bytes are 272 bits and 55 base32 characters carry 275, so the
 * last character holds three unused bits: only {@code a}, {@code i}, {@code q} and {@code y} can end a
 * well-formed id. A decoder that ignored that would accept eight spellings of one account, which ADM-001 L4
 * forbids, so a parse is a pattern match followed by a re-encode and compare.
 *
 * <p>The resolver never takes an accountId from a caller as the storage key: it re-derives the string from
 * the raw bytes carried inside the signed record. This class is what makes those two operations the same
 * function.
 */
public final class AccountId {

    /** ASCII prefix, outside the base32 alphabet. */
    public static final String PREFIX = "ga1";

    /** The raw bytes under the base32: format version, root class, then the 32-byte digest. */
    public static final int RAW_LENGTH = 34;

    /** The prefix plus 55 base32 characters. */
    public static final int ENCODED_LENGTH = 58;

    /** accountId format version, the first raw byte. */
    public static final byte FORMAT_VERSION = 0x01;

    /** Root class 0x00: a bootstrap id, minted for an account that predates account authority (L5). */
    public static final byte CLASS_BOOTSTRAP = 0x00;

    /** Root class 0x01: a genesis-rooted id, derived from an on-device AccountGenesis (L4). */
    public static final byte CLASS_GENESIS = 0x01;

    /** The canonical spelling: 54 free base32 characters and a last one whose low three bits are zero. */
    public static final Pattern CANONICAL = Pattern.compile("^ga1[a-z2-7]{54}[aiqy]$");

    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

    private AccountId() {}

    /** Encode the 34 raw bytes as the canonical id. This is the only way the resolver mints the key. */
    public static String encode(byte[] raw) {
        if (raw == null || raw.length != RAW_LENGTH) {
            throw new IllegalArgumentException("an accountId is exactly " + RAW_LENGTH + " raw bytes");
        }
        StringBuilder out = new StringBuilder(ENCODED_LENGTH).append(PREFIX);
        int buffer = 0;
        int bits = 0;
        for (byte b : raw) {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out.append(ALPHABET.charAt((buffer >>> bits) & 0x1F));
            }
        }
        if (bits > 0) {
            out.append(ALPHABET.charAt((buffer << (5 - bits)) & 0x1F));
        }
        return out.toString();
    }

    /** True when this is the one spelling of the account it names: pattern, then re-encode and compare. */
    public static boolean isCanonical(String accountId) {
        if (accountId == null || !CANONICAL.matcher(accountId).matches()) {
            return false;
        }
        byte[] raw = rawBytes(accountId);
        return raw != null && encode(raw).equals(accountId);
    }

    /** The raw bytes of a canonical id; a non-canonical spelling is refused, never repaired. */
    public static byte[] decode(String accountId) {
        byte[] raw = isCanonical(accountId) ? rawBytes(accountId) : null;
        if (raw == null) {
            throw new IllegalArgumentException("not a canonical accountId");
        }
        return raw;
    }

    /** The root class byte of raw id bytes: {@link #CLASS_BOOTSTRAP} or {@link #CLASS_GENESIS}. */
    public static byte rootClass(byte[] raw) {
        if (raw == null || raw.length != RAW_LENGTH) {
            throw new IllegalArgumentException("an accountId is exactly " + RAW_LENGTH + " raw bytes");
        }
        return raw[1];
    }

    /** Decode without the canonical check; null when a character or the trailing bits are wrong. */
    private static byte[] rawBytes(String accountId) {
        byte[] out = new byte[RAW_LENGTH];
        int buffer = 0;
        int bits = 0;
        int written = 0;
        for (int i = PREFIX.length(); i < accountId.length(); i++) {
            int value = ALPHABET.indexOf(accountId.charAt(i));
            if (value < 0) {
                return null;
            }
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                if (written == RAW_LENGTH) {
                    return null;
                }
                out[written++] = (byte) ((buffer >>> bits) & 0xFF);
            }
        }
        // The leftover bits are padding and must be zero, which is what leaves one spelling per account.
        if (written != RAW_LENGTH || (buffer & ((1 << bits) - 1)) != 0) {
            return null;
        }
        return out;
    }
}
