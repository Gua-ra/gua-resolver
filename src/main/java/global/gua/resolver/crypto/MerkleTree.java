package global.gua.resolver.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * RFC 6962 (Certificate Transparency) Merkle tree hashing — the tamper-evidence primitive behind the
 * transparency log (§5). Domain-separated so leaf and interior hashes can't be confused:
 * {@code leafHash = SHA256(0x00 || data)}, {@code nodeHash = SHA256(0x01 || left || right)}.
 *
 * <p>Provides the Merkle Tree Hash (root) and the consistency proof + verification that lets a mirror
 * prove a new checkpoint is an append-only extension of an older one (no rewritten history / split view).
 */
public final class MerkleTree {

    private static final byte[] LEAF_PREFIX = {0x00};
    private static final byte[] NODE_PREFIX = {0x01};
    private static final HexFormat HEX = HexFormat.of();

    private MerkleTree() {}

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String sha256Hex(String data) {
        return HEX.formatHex(sha256().digest(data.getBytes(StandardCharsets.UTF_8)));
    }

    /** RFC 6962 leaf hash (hex) for arbitrary leaf data. */
    public static String leafHash(byte[] data) {
        MessageDigest d = sha256();
        d.update(LEAF_PREFIX);
        d.update(data);
        return HEX.formatHex(d.digest());
    }

    private static byte[] nodeHash(byte[] left, byte[] right) {
        MessageDigest d = sha256();
        d.update(NODE_PREFIX);
        d.update(left);
        d.update(right);
        return d.digest();
    }

    /**
     * Merkle Tree Hash (RFC 6962 §2.1) over {@code leafHashes} (each a hex leaf hash). Returns the root as
     * hex. The empty tree hashes to SHA256 of the empty string.
     */
    public static String root(List<String> leafHashes) {
        if (leafHashes.isEmpty()) {
            return HEX.formatHex(sha256().digest(new byte[0]));
        }
        List<byte[]> level = new ArrayList<>(leafHashes.size());
        for (String h : leafHashes) {
            level.add(HEX.parseHex(h));
        }
        return HEX.formatHex(mth(level));
    }

    /** Recursive MTH over already-leaf-hashed nodes, splitting at the largest power of two < n. */
    private static byte[] mth(List<byte[]> nodes) {
        int n = nodes.size();
        if (n == 1) {
            return nodes.get(0);
        }
        int k = largestPowerOfTwoLessThan(n);
        byte[] left = mth(nodes.subList(0, k));
        byte[] right = mth(nodes.subList(k, n));
        return nodeHash(left, right);
    }

    private static int largestPowerOfTwoLessThan(int n) {
        int k = 1;
        while (k << 1 < n) {
            k <<= 1;
        }
        return k;
    }

    /**
     * RFC 6962 §2.1.2 consistency proof between a tree of {@code first} leaves and one of {@code second}
     * leaves (first &le; second). Returns the list of hex node hashes the verifier needs.
     */
    public static List<String> consistencyProof(List<String> leafHashes, int first, int second) {
        if (first < 0 || second < first || second > leafHashes.size()) {
            throw new IllegalArgumentException("invalid consistency proof range");
        }
        List<byte[]> nodes = new ArrayList<>(second);
        for (int i = 0; i < second; i++) {
            nodes.add(HEX.parseHex(leafHashes.get(i)));
        }
        List<byte[]> proof = new ArrayList<>();
        subproof(first, nodes, true, proof);
        List<String> out = new ArrayList<>(proof.size());
        for (byte[] p : proof) {
            out.add(HEX.formatHex(p));
        }
        return out;
    }

    private static void subproof(int m, List<byte[]> nodes, boolean startFromOldRoot, List<byte[]> proof) {
        int n = nodes.size();
        if (m == n) {
            if (!startFromOldRoot) {
                proof.add(mth(nodes));
            }
            return;
        }
        int k = largestPowerOfTwoLessThan(n);
        if (m <= k) {
            subproof(m, nodes.subList(0, k), startFromOldRoot, proof);
            proof.add(mth(nodes.subList(k, n)));
        } else {
            subproof(m - k, nodes.subList(k, n), false, proof);
            proof.add(mth(nodes.subList(0, k)));
        }
    }

    /**
     * Verify a consistency proof: that {@code newRoot} (of {@code second} leaves) is an append-only
     * extension of {@code oldRoot} (of {@code first} leaves). This is the check a mirror runs against the
     * authority so a forked/rewritten history is detected.
     */
    public static boolean verifyConsistency(int first, int second, String oldRoot, String newRoot,
                                            List<String> proof) {
        if (first == 0) {
            return second >= 0;  // everything is consistent with the empty tree
        }
        if (first == second) {
            return proof.isEmpty() && oldRoot.equals(newRoot);
        }
        if (first > second || proof.isEmpty()) {
            return false;
        }

        List<byte[]> path = new ArrayList<>();
        for (String p : proof) {
            path.add(HEX.parseHex(p));
        }

        // RFC 6962 §2.1.2 verification algorithm.
        boolean firstIsPowerOfTwo = (first & (first - 1)) == 0;
        int idx = 0;
        List<byte[]> seed = new ArrayList<>();
        if (firstIsPowerOfTwo) {
            seed.add(HEX.parseHex(oldRoot));
        } else {
            seed.add(path.get(idx++));
        }

        byte[] fr = seed.get(0);   // running hash toward old root
        byte[] sr = seed.get(0);   // running hash toward new root
        int fn = first - 1;
        int sn = second - 1;
        while ((fn & 1) == 1) {
            fn >>= 1;
            sn >>= 1;
        }
        while (idx < path.size()) {
            byte[] node = path.get(idx++);
            if ((fn & 1) == 1 || fn == sn) {
                fr = nodeHash(node, fr);
                sr = nodeHash(node, sr);
                while ((fn & 1) == 0 && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            } else {
                sr = nodeHash(sr, node);
            }
            fn >>= 1;
            sn >>= 1;
        }

        return HEX.formatHex(fr).equals(oldRoot)
                && HEX.formatHex(sr).equals(newRoot)
                && sn == 0;
    }
}
