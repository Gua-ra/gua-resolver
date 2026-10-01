/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.util.regex.Pattern;

/** {@code "ga1" || base32(0x01 || class || SHA-256(genesis bytes))}, RFC 4648 lowercase, unpadded. */
public final class AccountId {

    public static final String PREFIX = "ga1";

    public static final int RAW_LENGTH = 34;

    public static final int ENCODED_LENGTH = 58;

    public static final byte FORMAT_VERSION = 0x01;

    public static final byte CLASS_BOOTSTRAP = 0x00;

    public static final byte CLASS_GENESIS = 0x01;

    public static final Pattern CANONICAL = Pattern.compile("^ga1[a-z2-7]{54}[aiqy]$");

    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

    private AccountId() {}

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

    public static boolean isCanonical(String accountId) {
        if (accountId == null || !CANONICAL.matcher(accountId).matches()) {
            return false;
        }
        byte[] raw = rawBytes(accountId);
        return raw != null && encode(raw).equals(accountId);
    }

    public static byte[] decode(String accountId) {
        byte[] raw = isCanonical(accountId) ? rawBytes(accountId) : null;
        if (raw == null) {
            throw new IllegalArgumentException("not a canonical accountId");
        }
        return raw;
    }

    public static byte rootClass(byte[] raw) {
        if (raw == null || raw.length != RAW_LENGTH) {
            throw new IllegalArgumentException("an accountId is exactly " + RAW_LENGTH + " raw bytes");
        }
        return raw[1];
    }

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
        // The leftover bits are padding and must be zero.
        if (written != RAW_LENGTH || (buffer & ((1 << bits) - 1)) != 0) {
            return null;
        }
        return out;
    }
}
