package global.gua.resolver.crypto;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RFC 6962 Merkle behaviour: a stable root, and consistency proofs that accept genuine append-only
 * extensions while rejecting a rewritten/forked history — the tamper-evidence the transparency log relies
 * on (§5).
 */
class MerkleTreeTest {

    private static List<String> leaves(int n) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(MerkleTree.leafHash(("event-" + i).getBytes(StandardCharsets.UTF_8)));
        }
        return out;
    }

    @Test
    void rootIsDeterministicAndOrderSensitive() {
        assertThat(MerkleTree.root(leaves(5))).isEqualTo(MerkleTree.root(leaves(5)));
        List<String> reordered = new ArrayList<>(leaves(5));
        java.util.Collections.swap(reordered, 0, 4);
        assertThat(MerkleTree.root(reordered)).isNotEqualTo(MerkleTree.root(leaves(5)));
    }

    @Test
    void consistencyProofAcceptsGenuineExtension() {
        List<String> all = leaves(9);
        for (int first = 1; first <= 9; first++) {
            for (int second = first; second <= 9; second++) {
                String oldRoot = MerkleTree.root(all.subList(0, first));
                String newRoot = MerkleTree.root(all.subList(0, second));
                List<String> proof = MerkleTree.consistencyProof(all, first, second);
                assertThat(MerkleTree.verifyConsistency(first, second, oldRoot, newRoot, proof))
                        .as("consistency %d -> %d", first, second)
                        .isTrue();
            }
        }
    }

    @Test
    void consistencyProofRejectsRewrittenHistory() {
        List<String> original = leaves(6);
        String oldRoot = MerkleTree.root(original.subList(0, 3));
        List<String> proof = MerkleTree.consistencyProof(original, 3, 6);

        // Tamper with leaf 1 (within the "old" prefix) then re-extend: the old root no longer matches.
        List<String> tampered = new ArrayList<>(original);
        tampered.set(1, MerkleTree.leafHash("forged".getBytes(StandardCharsets.UTF_8)));
        String forgedNewRoot = MerkleTree.root(tampered);

        assertThat(MerkleTree.verifyConsistency(3, 6, oldRoot, forgedNewRoot, proof)).isFalse();
    }
}
