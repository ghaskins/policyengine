//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"fmt"
	"sort"

	"github.com/manetu/policyengine/pkg/audit/verify"
)

// recomputeBatchRoot rebuilds the batch Merkle tree from leaves (as returned
// by GET /api/v1/notary/leaves) and returns its root hash bytes -- scan step
// 7. partition and notaryTsTo come from the root's own signed payload
// (notary_ts_from == notary_ts_to for every root this codebase writes, a
// single point-in-time seal per batch/heartbeat -- see batcher.clj).
// leaves is sorted by LeafIndex ascending before building the tree, since
// leaf_index IS the tree's array order and the /leaves endpoint does not
// itself guarantee response order.
func recomputeBatchRoot(partition int, notaryTsTo int64, leaves []LeafRow) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("scan: recompute-batch-root: no leaves to build a tree from")
	}
	sorted := make([]LeafRow, len(leaves))
	copy(sorted, leaves)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].LeafIndex < sorted[j].LeafIndex })

	leafHashes := make([][]byte, len(sorted))
	for i, l := range sorted {
		if l.LeafIndex != int64(i) {
			return nil, fmt.Errorf("scan: recompute-batch-root: leaf_index values are not a dense 0..n-1 sequence (got %d at position %d)", l.LeafIndex, i)
		}
		lh, err := verify.PositionedLeafHash(int64(partition), l.Seq, l.LeafIndex, notaryTsTo, l.LeafHashB64)
		if err != nil {
			return nil, err
		}
		leafHashes[i] = lh
	}
	tree := verify.BuildTree(leafHashes)
	return verify.Root(tree)
}
