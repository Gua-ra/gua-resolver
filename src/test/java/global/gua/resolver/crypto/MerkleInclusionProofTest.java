/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.crypto;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The audit path is the new primitive an authority-head verifier rests on, so it is tested the way a proof
 * system has to be: every leaf of every tree size in a range verifies, and every way of altering a proof fails.
 *
 * <p>A proof checker that only accepts valid proofs is useless; what matters is that it refuses a proof for a
 * leaf the tree does not carry, which is the exact refusal
 * {@code AccountAuthorityHeadCheckTest} relies on for "a head the log does not carry".
 */
class MerkleInclusionProofTest {

    private static List<String> leaves(int n) {
        List<String> out = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            out.add(MerkleTree.leafHash(("leaf-" + i).getBytes(StandardCharsets.UTF_8)));
        }
        return out;
    }

    @Test
    void everyLeafOfEveryTreeSizeUpTo33Verifies() {
        for (int size = 1; size <= 33; size++) {
            List<String> leaves = leaves(size);
            String root = MerkleTree.root(leaves);
            for (int index = 0; index < size; index++) {
                List<String> proof = MerkleTree.inclusionProof(leaves, index);
                assertThat(MerkleTree.verifyInclusion(index, size, leaves.get(index), root, proof))
                        .as("size %d index %d", size, index)
                        .isTrue();
            }
        }
    }

    @Test
    void aSingleLeafTreeNeedsNoPathAtAll() {
        List<String> leaves = leaves(1);
        assertThat(MerkleTree.inclusionProof(leaves, 0)).isEmpty();
        assertThat(MerkleTree.verifyInclusion(0, 1, leaves.get(0), MerkleTree.root(leaves), List.of()))
                .isTrue();
    }

    @Test
    void theProofDepthIsLogarithmic() {
        List<String> leaves = leaves(1024);
        assertThat(MerkleTree.inclusionProof(leaves, 512)).hasSize(10);
    }

    @Test
    void aLeafTheTreeDoesNotCarryIsRefused() {
        List<String> leaves = leaves(9);
        String root = MerkleTree.root(leaves);
        String absent = MerkleTree.leafHash("not-in-this-tree".getBytes(StandardCharsets.UTF_8));
        // The path is a real path; only the leaf is foreign. This is the shape of a forged head: a genuine
        // audit path lifted from the log, presented for bytes the log never committed.
        List<String> proof = MerkleTree.inclusionProof(leaves, 4);
        assertThat(MerkleTree.verifyInclusion(4, 9, absent, root, proof)).isFalse();
    }

    @Test
    void aProofForOneIndexDoesNotVerifyAtAnother() {
        List<String> leaves = leaves(8);
        String root = MerkleTree.root(leaves);
        List<String> proof = MerkleTree.inclusionProof(leaves, 3);
        assertThat(MerkleTree.verifyInclusion(3, 8, leaves.get(3), root, proof)).isTrue();
        assertThat(MerkleTree.verifyInclusion(4, 8, leaves.get(3), root, proof)).isFalse();
        assertThat(MerkleTree.verifyInclusion(3, 8, leaves.get(4), root, proof)).isFalse();
    }

    @Test
    void everyAlterationOfAValidProofFails() {
        List<String> leaves = leaves(11);
        String root = MerkleTree.root(leaves);
        List<String> proof = MerkleTree.inclusionProof(leaves, 6);
        assertThat(MerkleTree.verifyInclusion(6, 11, leaves.get(6), root, proof)).isTrue();

        // one node flipped
        for (int i = 0; i < proof.size(); i++) {
            List<String> tampered = new ArrayList<>(proof);
            tampered.set(i, MerkleTree.leafHash(("forged-" + i).getBytes(StandardCharsets.UTF_8)));
            assertThat(MerkleTree.verifyInclusion(6, 11, leaves.get(6), root, tampered))
                    .as("node %d replaced", i)
                    .isFalse();
        }
        // reordered
        List<String> reversed = new ArrayList<>(proof);
        java.util.Collections.reverse(reversed);
        assertThat(MerkleTree.verifyInclusion(6, 11, leaves.get(6), root, reversed)).isFalse();
        // truncated and extended: every entry must be consumed, and no more
        assertThat(MerkleTree.verifyInclusion(6, 11, leaves.get(6), root,
                proof.subList(0, proof.size() - 1))).isFalse();
        List<String> extended = new ArrayList<>(proof);
        extended.add(proof.get(0));
        assertThat(MerkleTree.verifyInclusion(6, 11, leaves.get(6), root, extended)).isFalse();
        // and a different root
        assertThat(MerkleTree.verifyInclusion(6, 11, leaves.get(6),
                MerkleTree.root(leaves(12)), proof)).isFalse();
    }

    @Test
    void aProofFromASmallerTreeDoesNotVerifyAgainstALargerOne() {
        List<String> small = leaves(5);
        List<String> large = leaves(12);
        List<String> proof = MerkleTree.inclusionProof(small, 2);
        assertThat(MerkleTree.verifyInclusion(2, 12, small.get(2), MerkleTree.root(large), proof))
                .isFalse();
    }

    @Test
    void impossibleArgumentsAreRefusedRatherThanThrown() {
        List<String> leaves = leaves(4);
        String root = MerkleTree.root(leaves);
        List<String> proof = MerkleTree.inclusionProof(leaves, 1);
        assertThat(MerkleTree.verifyInclusion(-1, 4, leaves.get(1), root, proof)).isFalse();
        assertThat(MerkleTree.verifyInclusion(4, 4, leaves.get(1), root, proof)).isFalse();
        assertThat(MerkleTree.verifyInclusion(1, 0, leaves.get(1), root, proof)).isFalse();
        assertThat(MerkleTree.verifyInclusion(1, 4, leaves.get(1), root, null)).isFalse();
        assertThat(MerkleTree.verifyInclusion(1, 4, "not-hex", root, proof)).isFalse();
        assertThat(MerkleTree.verifyInclusion(1, 4, leaves.get(1), root, List.of("not-hex"))).isFalse();
        // A path longer than any tree is deep is refused without walking it.
        List<String> absurd = new ArrayList<>();
        for (int i = 0; i < 65; i++) {
            absurd.add(root);
        }
        assertThat(MerkleTree.verifyInclusion(1, 4, leaves.get(1), root, absurd)).isFalse();
    }

    @Test
    void anIndexOutsideTheTreeCannotBeProved() {
        List<String> leaves = leaves(3);
        assertThatThrownBy(() -> MerkleTree.inclusionProof(leaves, 3))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MerkleTree.inclusionProof(leaves, -1))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
