//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func leafHashes(n int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = LeafHash([]byte{byte(i)})
	}
	return out
}

func TestBuildTreeSingleLeaf(t *testing.T) {
	t.Parallel()

	leaves := leafHashes(1)
	tree := BuildTree(leaves)
	root, err := Root(tree)
	require.NoError(t, err)
	proof, err := InclusionProof(tree, 0)
	require.NoError(t, err)
	assert.Empty(t, proof, "a single-leaf tree's root IS the leaf node hash; no audit path")
	assert.True(t, VerifyInclusion(root, leaves[0], proof))
}

func TestBuildTreeInclusionAllSizes(t *testing.T) {
	t.Parallel()

	// Cover both even and odd leaf counts to exercise RFC 6962 odd-count
	// promotion at every level.
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 13, 16} {
		n := n
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			t.Parallel()

			leaves := leafHashes(n)
			tree := BuildTree(leaves)
			root, err := Root(tree)
			require.NoError(t, err)
			for i := 0; i < n; i++ {
				proof, err := InclusionProof(tree, i)
				require.NoError(t, err)
				assert.Truef(t, VerifyInclusion(root, leaves[i], proof), "leaf %d/%d failed to verify", i, n)
			}
		})
	}
}

func TestVerifyInclusionRejectsTampering(t *testing.T) {
	t.Parallel()

	leaves := leafHashes(5)
	tree := BuildTree(leaves)
	root, err := Root(tree)
	require.NoError(t, err)
	proof, err := InclusionProof(tree, 2)
	require.NoError(t, err)
	require.True(t, VerifyInclusion(root, leaves[2], proof))

	// Wrong leaf.
	assert.False(t, VerifyInclusion(root, leaves[3], proof))

	// Tampered proof step.
	tampered := make([]ProofStep, len(proof))
	copy(tampered, proof)
	tampered[0] = ProofStep{Hash: LeafHash([]byte("evil")), Side: tampered[0].Side}
	assert.False(t, VerifyInclusion(root, leaves[2], tampered))

	// Wrong root.
	assert.False(t, VerifyInclusion(LeafHash([]byte("not-the-root")), leaves[2], proof))
}

// TestVerifyInclusionRejectsEmptyProofOnMultiLeafTree is the multi-leaf
// counterpart to TestBuildTreeSingleLeaf's "empty proof valid" case: an empty
// proof is only a legitimate inclusion proof when the leaf IS the root
// (single-leaf tree). For any larger tree, an empty proof must fail --
// otherwise a stripped audit path could be mistaken for a valid one-leaf
// tree's proof.
func TestVerifyInclusionRejectsEmptyProofOnMultiLeafTree(t *testing.T) {
	t.Parallel()

	leaves := leafHashes(5)
	tree := BuildTree(leaves)
	root, err := Root(tree)
	require.NoError(t, err)
	assert.False(t, VerifyInclusion(root, leaves[2], nil), "empty proof must not verify against a multi-leaf root")
}

// TestVerifyInclusionRejectsWrongLengthProof proves a genuine proof's length
// is itself load-bearing: neither truncating it (dropping a real level) nor
// extending it (appending a bogus level) may still verify.
func TestVerifyInclusionRejectsWrongLengthProof(t *testing.T) {
	t.Parallel()

	leaves := leafHashes(8)
	tree := BuildTree(leaves)
	root, err := Root(tree)
	require.NoError(t, err)
	proof, err := InclusionProof(tree, 3)
	require.NoError(t, err)
	require.True(t, VerifyInclusion(root, leaves[3], proof))
	require.Len(t, proof, 3, "8-leaf tree has 3 levels above the leaves")

	truncated := proof[:len(proof)-1]
	assert.False(t, VerifyInclusion(root, leaves[3], truncated), "a truncated (too-short) proof must not verify")

	extended := append(append([]ProofStep{}, proof...), ProofStep{Hash: LeafHash([]byte("extra")), Side: SideRight})
	assert.False(t, VerifyInclusion(root, leaves[3], extended), "an extended (too-long) proof must not verify")
}

func TestBuildTreePanicsOnEmpty(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { BuildTree(nil) })
}

func TestRootRejectsEmptyTree(t *testing.T) {
	t.Parallel()

	_, err := Root(nil)
	assert.Error(t, err)
}

func TestInclusionProofRejectsOutOfRangeLeafIndex(t *testing.T) {
	t.Parallel()

	tree := BuildTree(leafHashes(3))

	_, err := InclusionProof(tree, -1)
	assert.Error(t, err)

	_, err = InclusionProof(tree, len(tree[0]))
	assert.Error(t, err)
}

// TestMerkleTreeShapeKnownVector locks in the exact odd-count promotion
// behavior against a hand-worked 3-leaf tree, so a future refactor can't
// silently change tree shape while inclusion proofs still happen to verify.
func TestMerkleTreeShapeKnownVector(t *testing.T) {
	t.Parallel()

	leaves := leafHashes(3)
	tree := BuildTree(leaves)
	require.Len(t, tree, 3, "3 leaves -> level0(3) -> level1(2, promoted+paired) -> level2(1, root)")
	require.Len(t, tree[0], 3)
	require.Len(t, tree[1], 2)
	require.Len(t, tree[2], 1)

	// level1[0] = node_hash(leaf0, leaf1); level1[1] = leaf2 promoted unchanged.
	expectedPair := nodeHash(leafNodeHash(leaves[0]), leafNodeHash(leaves[1]))
	expectedPromoted := leafNodeHash(leaves[2])
	assert.Equal(t, expectedPair, tree[1][0])
	assert.Equal(t, expectedPromoted, tree[1][1])

	// Leaf 2's proof carries no step for its own promotion, only the final pairing.
	proof, err := InclusionProof(tree, 2)
	require.NoError(t, err)
	require.Len(t, proof, 1)
	assert.Equal(t, tree[1][0], proof[0].Hash)
	assert.Equal(t, SideLeft, proof[0].Side)
}

// TestMerkleTreeShapeKnownVectorSideRight is the SideRight counterpart to
// TestMerkleTreeShapeKnownVector's hand-pinned SideLeft case. Without this,
// nothing in the suite hand-verifies a SideRight step: every other test
// derives its expected side from InclusionProof's own output, so a
// systematic left/right swap in InclusionProof (or in VerifyInclusion's
// consumption of Side) would go undetected.
func TestMerkleTreeShapeKnownVectorSideRight(t *testing.T) {
	t.Parallel()

	leaves := leafHashes(3)
	tree := BuildTree(leaves)
	require.Len(t, tree, 3)

	// Leaf 0 is paired (not promoted) at both levels, so both its proof
	// steps have their sibling on the right: level0 sibling is leaf1's
	// node hash; level1 sibling is leaf2's promoted node hash.
	proof, err := InclusionProof(tree, 0)
	require.NoError(t, err)
	require.Len(t, proof, 2)
	assert.Equal(t, leafNodeHash(leaves[1]), proof[0].Hash)
	assert.Equal(t, SideRight, proof[0].Side)
	assert.Equal(t, leafNodeHash(leaves[2]), proof[1].Hash)
	assert.Equal(t, SideRight, proof[1].Side)
}

// TestVerifyInclusionRejectsSideSwap proves left/right ordering is
// cryptographically load-bearing: flipping a valid proof step's Side while
// leaving its Hash unchanged must be rejected. Without this test, a
// hypothetical Left/Right-swapped VerifyInclusion implementation would pass
// every other test in the suite, since none of them independently pin which
// side a sibling belongs on.
func TestVerifyInclusionRejectsSideSwap(t *testing.T) {
	t.Parallel()

	leaves := leafHashes(5)
	tree := BuildTree(leaves)
	root, err := Root(tree)
	require.NoError(t, err)
	proof, err := InclusionProof(tree, 2)
	require.NoError(t, err)
	require.NotEmpty(t, proof)
	require.True(t, VerifyInclusion(root, leaves[2], proof))

	swapped := make([]ProofStep, len(proof))
	copy(swapped, proof)
	if swapped[0].Side == SideLeft {
		swapped[0].Side = SideRight
	} else {
		swapped[0].Side = SideLeft
	}
	assert.False(t, VerifyInclusion(root, leaves[2], swapped))
}
