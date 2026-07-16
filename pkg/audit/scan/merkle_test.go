//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manetu/policyengine/pkg/audit/verify"
)

func TestRecomputeBatchRootMatchesBuiltTree(t *testing.T) {
	partition := 1
	notaryTs := int64(999)
	leaves := make([]LeafRow, 4)
	rawHashes := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		h := sha256.Sum256([]byte{byte(i)})
		rawHashes[i] = h[:]
		leaves[i] = LeafRow{ID: "id", Seq: int64(10 + i), LeafIndex: int64(i), LeafHashB64: b64urlEncode(h[:])}
	}
	positioned := make([][]byte, 4)
	for i, l := range leaves {
		ph, err := verify.PositionedLeafHash(int64(partition), l.Seq, l.LeafIndex, notaryTs, l.LeafHashB64)
		require.NoError(t, err)
		positioned[i] = ph
	}
	tree := verify.BuildTree(positioned)
	wantRoot, err := verify.Root(tree)
	require.NoError(t, err)

	gotRoot, err := recomputeBatchRoot(partition, notaryTs, leaves)
	require.NoError(t, err)
	assert.Equal(t, wantRoot, gotRoot)
}

func TestRecomputeBatchRootOrderIndependentOfResponseOrder(t *testing.T) {
	partition := 0
	notaryTs := int64(1)
	l0 := LeafRow{ID: "a", Seq: 0, LeafIndex: 0, LeafHashB64: b64urlEncode([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))}
	l1 := LeafRow{ID: "b", Seq: 1, LeafIndex: 1, LeafHashB64: b64urlEncode([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))}

	inOrder, err := recomputeBatchRoot(partition, notaryTs, []LeafRow{l0, l1})
	require.NoError(t, err)
	reversed, err := recomputeBatchRoot(partition, notaryTs, []LeafRow{l1, l0})
	require.NoError(t, err)
	assert.Equal(t, inOrder, reversed, "leaf_index, not response order, must determine tree position")
}

func TestRecomputeBatchRootRejectsNonDenseLeafIndex(t *testing.T) {
	leaves := []LeafRow{
		{ID: "a", Seq: 0, LeafIndex: 0, LeafHashB64: b64urlEncode([]byte("x"))},
		{ID: "b", Seq: 2, LeafIndex: 2, LeafHashB64: b64urlEncode([]byte("y"))}, // gap at index 1
	}
	_, err := recomputeBatchRoot(0, 1, leaves)
	assert.Error(t, err)
}
