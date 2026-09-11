package global.gua.resolver.abuse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Derives the per-client rate-limit key for {@code POST /resolve} from the request's network origin.
 *
 * <p>The service runs behind the ingress, which sets {@code X-Forwarded-For}. A caller can send its own
 * {@code X-Forwarded-For}; the ingress then appends the address it actually saw the connection come from,
 * so the LAST entry is the only one the ingress vouches for and every earlier entry is caller-controlled.
 * Taking the last entry therefore cannot be spoofed through the ingress, and a request that reaches the pod
 * without the header (a port-forward, an in-cluster caller) falls back to the socket peer address. The rule
 * assumes exactly one trusted proxy hop, which is how the ingress is deployed; a second trusted hop would
 * make the last entry the first proxy's address and fold every client into one key.
 *
 * <p>IPv6 clients are keyed by their /64: a single subscriber is routinely handed a whole /64, and keying on
 * the full address would hand an attacker 2^64 free buckets. IPv4-mapped IPv6 literals key by the embedded
 * IPv4 address so a dual-stack listener does not fold every IPv4 client into one key.
 */
public final class ClientKey {

    public static final String FORWARDED_FOR = "X-Forwarded-For";
    static final String UNKNOWN = "unknown";
    private static final int LOG_HANDLE_CHARS = 12;

    private ClientKey() {}

    public static String of(HttpServletRequest request) {
        return of(request.getHeader(FORWARDED_FOR), request.getRemoteAddr());
    }

    static String of(String forwardedFor, String remoteAddr) {
        String candidate = lastAddress(forwardedFor);
        if (candidate == null) {
            candidate = remoteAddr == null ? null : remoteAddr.trim();
        }
        if (candidate == null || candidate.isEmpty()) {
            return UNKNOWN;
        }
        return normalize(candidate);
    }

    /**
     * Truncated SHA-256 of the key: a correlation handle for logs and alerts, so raw client addresses stay out
     * of them. It is a handle, not anonymisation: the input space is small enough to brute-force.
     */
    public static String logHandle(String key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, LOG_HANDLE_CHARS);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** The last non-empty, comma-separated entry, or null when the header is absent or has none. */
    static String lastAddress(String forwardedFor) {
        if (forwardedFor == null) {
            return null;
        }
        String[] parts = forwardedFor.split(",");
        for (int i = parts.length - 1; i >= 0; i--) {
            String part = parts[i].trim();
            if (!part.isEmpty()) {
                return part;
            }
        }
        return null;
    }

    /** Strip a port suffix, then key IPv6 by /64 (or embedded IPv4); anything else is used verbatim. */
    static String normalize(String address) {
        String a = address;
        if (a.startsWith("[")) {                                             // "[v6]" or "[v6]:port"
            int end = a.indexOf(']');
            a = end > 0 ? a.substring(1, end) : a.substring(1);
        } else if (a.indexOf(':') >= 0 && a.indexOf(':') == a.lastIndexOf(':')) {   // "v4:port"
            a = a.substring(0, a.indexOf(':'));
        }
        if (a.indexOf(':') >= 0) {
            String v6 = ipv6Key(a);
            if (v6 != null) {
                return v6;
            }
        }
        return a.toLowerCase(Locale.ROOT);
    }

    /** The /64 prefix of an IPv6 literal, the embedded IPv4 of a mapped address, or null when unparseable. */
    static String ipv6Key(String literal) {
        String s = literal;
        int zone = s.indexOf('%');
        if (zone >= 0) {
            s = s.substring(0, zone);
        }
        int[] g = parseIpv6(s);
        if (g == null) {
            return null;
        }
        if (g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0xffff) {
            return (g[6] >> 8) + "." + (g[6] & 0xff) + "." + (g[7] >> 8) + "." + (g[7] & 0xff);
        }
        return String.format(Locale.ROOT, "%x:%x:%x:%x::/64", g[0], g[1], g[2], g[3]);
    }

    private static int[] parseIpv6(String s) {
        int gap = s.indexOf("::");
        if (gap >= 0 && s.indexOf("::", gap + 1) >= 0) {
            return null;                                                   // more than one "::"
        }
        int[] head = parseGroups(gap >= 0 ? s.substring(0, gap) : s);
        int[] tail = parseGroups(gap >= 0 ? s.substring(gap + 2) : "");
        if (head == null || tail == null) {
            return null;
        }
        int missing = 8 - head.length - tail.length;
        if (gap >= 0 ? missing < 1 : missing != 0) {
            return null;
        }
        int[] out = new int[8];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(tail, 0, out, 8 - tail.length, tail.length);
        return out;
    }

    /** Colon-separated 16-bit hex groups; a trailing dotted quad (mapped forms) expands to two groups. */
    private static int[] parseGroups(String s) {
        if (s.isEmpty()) {
            return new int[0];
        }
        String[] parts = s.split(":", -1);
        int[] out = new int[parts.length + 1];
        int n = 0;
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i];
            if (i == parts.length - 1 && p.indexOf('.') >= 0) {
                int[] v4 = parseIpv4(p);
                if (v4 == null) {
                    return null;
                }
                out[n++] = (v4[0] << 8) | v4[1];
                out[n++] = (v4[2] << 8) | v4[3];
            } else {
                if (p.isEmpty() || p.length() > 4 || !isHex(p)) {
                    return null;
                }
                out[n++] = Integer.parseInt(p, 16);
            }
        }
        return Arrays.copyOf(out, n);
    }

    private static int[] parseIpv4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        int[] out = new int[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3 || !isDecimal(p)) {
                return null;
            }
            int v = Integer.parseInt(p);
            if (v > 255) {
                return null;
            }
            out[i] = v;
        }
        return out;
    }

    private static boolean isHex(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.digit(s.charAt(i), 16) < 0 || s.charAt(i) > 'f') {
                return false;
            }
        }
        return true;
    }

    private static boolean isDecimal(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }
}
