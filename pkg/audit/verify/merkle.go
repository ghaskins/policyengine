//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// Side identifies which side of a Merkle audit-path step a sibling hash
// occupies relative to the node being folded upward.
type Side int

// Sibling positions for a Merkle audit-path step.
const (
	SideLeft Side = iota
	SideRight
)

// ProofStep is one sibling hash in a Merkle inclusion audit path.
type ProofStep struct {
	Hash []byte
	Side Side
}

// leafNodeHash applies the RFC 6962 §2.1 leaf domain separator, preventing
// second-preimage attacks between leaves and internal nodes.
func leafNodeHash(data []byte) []byte {
	h := sha256.Sum256(concatBytes([]byte{0x00}, data))
	return h[:]
}

// nodeHash applies the RFC 6962 §2.1 internal-node domain separator.
func nodeHash(left, right []byte) []byte {
	h := sha256.Sum256(concatBytes([]byte{0x01}, left, right))
	return h[:]
}

// nextLevel pairs adjacent nodes and promotes the last node unchanged when
// the level has an odd count (RFC 6962 odd-count rule; no duplicate-last-leaf
// padding).
func nextLevel(level [][]byte) [][]byte {
	n := len(level)
	result := make([][]byte, 0, (n+1)/2)
	for i := 0; i < n; {
		if i == n-1 {
			result = append(result, level[i])
			i++
		} else {
			result = append(result, nodeHash(level[i], level[i+1]))
			i += 2
		}
	}
	return result
}

// BuildTree builds an RFC 6962-compliant binary Merkle tree from a sequence
// of leaf-data byte slices. Level 0 holds SHA-256(0x00||leafData) for each
// leaf (leaf domain separation); higher levels use SHA-256(0x01||left||right)
// (internal domain separation). Odd counts promote the last node unchanged.
// Returns the tree as a slice of levels: levels[0] is the leaf-node hashes,
// levels[len(levels)-1] is [root]. Panics if leafHashes is empty -- the
// caller guarantees non-empty batches; idle partitions use a heartbeat
// sentinel path instead.
func BuildTree(leafHashes [][]byte) [][][]byte {
	if len(leafHashes) == 0 {
		panic("verify: BuildTree: leafHashes must not be empty")
	}
	level0 := make([][]byte, len(leafHashes))
	for i, lh := range leafHashes {
		level0[i] = leafNodeHash(lh)
	}
	levels := [][][]byte{level0}
	for len(levels[len(levels)-1]) > 1 {
		levels = append(levels, nextLevel(levels[len(levels)-1]))
	}
	return levels
}

// Root returns the 32-byte root hash from a tree built by BuildTree. Returns
// an error if tree is empty or nil.
func Root(tree [][][]byte) ([]byte, error) {
	if len(tree) == 0 {
		return nil, fmt.Errorf("verify: Root: tree must not be empty")
	}
	last := tree[len(tree)-1]
	if len(last) == 0 {
		return nil, fmt.Errorf("verify: Root: tree root level must not be empty")
	}
	return last[0], nil
}

// InclusionProof returns the audit path for the leaf at leafIndex. A
// promoted node (the last node in an odd-count level) has no sibling and
// produces no proof step. Returns an error if leafIndex is out of range for
// the tree's leaf level.
func InclusionProof(tree [][][]byte, leafIndex int) ([]ProofStep, error) {
	if len(tree) == 0 {
		return nil, fmt.Errorf("verify: InclusionProof: tree must not be empty")
	}
	if leafIndex < 0 || leafIndex >= len(tree[0]) {
		return nil, fmt.Errorf("verify: InclusionProof: leafIndex %d out of range [0, %d)", leafIndex, len(tree[0]))
	}
	var proof []ProofStep
	idx := leafIndex
	for l := 0; l < len(tree)-1; l++ {
		level := tree[l]
		n := len(level)
		if n%2 == 1 && idx == n-1 {
			// Promoted: last node in an odd-count level carries up unchanged.
			idx /= 2
			continue
		}
		var sibIdx int
		var side Side
		if idx%2 == 0 {
			sibIdx, side = idx+1, SideRight
		} else {
			sibIdx, side = idx-1, SideLeft
		}
		proof = append(proof, ProofStep{Hash: level[sibIdx], Side: side})
		idx /= 2
	}
	return proof, nil
}

// VerifyInclusion reports whether leafHash is a member of the tree with the
// given root hash, per the audit path produced by InclusionProof.
func VerifyInclusion(rootHash, leafHash []byte, proof []ProofStep) bool {
	cur := leafNodeHash(leafHash)
	for _, step := range proof {
		if step.Side == SideLeft {
			cur = nodeHash(step.Hash, cur)
		} else {
			cur = nodeHash(cur, step.Hash)
		}
	}
	return bytes.Equal(cur, rootHash)
}
