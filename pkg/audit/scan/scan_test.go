//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupClean(t *testing.T) (testKeyPair, *fakeAnchorClient, *fakeNotaryServer) {
	t.Helper()
	kp := genTestKeyPair(t)
	anchor := newFakeAnchorClient()
	ns := newFakeNotaryServer(t)

	b1 := buildBatch(t, kp, 0, 1, 0, 3, 1000, nil, nil)
	rootHash1, _ := getString(b1.root, "root_hash_b64")
	b2 := buildBatch(t, kp, 0, 1, 3, 2, 2000, "root-0", rootHash1)

	anchor.windows[0] = []EnumeratedRoot{
		{RootID: "root-0", Payload: b1.root},
		{RootID: "root-1", Payload: b2.root},
	}
	rootHash2, _ := getString(b2.root, "root_hash_b64")
	_ = rootHash2
	anchor.heads[0] = &AnchorPointer{RootID: "root-1", ToSeq: 4}

	ns.leaves["root-0"] = b1.leaves
	ns.leaves["root-1"] = b2.leaves

	return kp, anchor, ns
}

func TestScanCleanWindowNoFindings(t *testing.T) {
	kp, anchor, ns := setupClean(t)
	result, err := Scan(context.Background(), Config{
		Partitions:   []int{0},
		FromTS:       0,
		ToTS:         10000,
		Anchor:       anchor,
		Notary:       ns.client(),
		NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Empty(t, result.Findings)
	assert.Equal(t, 2, result.RootsWalked)
	assert.Equal(t, 5, result.LeavesCensused)
}

func TestScanBadRootSignatureIsFinding(t *testing.T) {
	kp, anchor, ns := setupClean(t)
	// Tamper the second root's signature.
	anchor.windows[0][1].Payload["root_signature_b64"] = anchor.windows[0][1].Payload["root_signature_b64"].(string) + "x"

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
	require.NotEmpty(t, result.Findings)
	assert.Equal(t, "root-signature", result.Findings[0].Kind)
}

func TestScanContiguityGapIsFinding(t *testing.T) {
	kp, anchor, ns := setupClean(t)
	// Break covered_range contiguity: root-1 should start at seq 3, force seq 5.
	cr := anchor.windows[0][1].Payload["covered_range"].(map[string]interface{})
	cr["from_seq"] = num(5)

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
	found := false
	for _, f := range result.Findings {
		if f.Kind == "contiguity" {
			found = true
		}
	}
	assert.True(t, found, "expected a contiguity finding, got %+v", result.Findings)
}

func TestScanTailTruncationIsFinding(t *testing.T) {
	kp, anchor, ns := setupClean(t)
	// Anchor-head claims a later to_seq than what was enumerated -- roots withheld.
	anchor.heads[0] = &AnchorPointer{RootID: "root-2", ToSeq: 99}

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
	found := false
	for _, f := range result.Findings {
		if f.Kind == "tail-truncation" {
			found = true
		}
	}
	assert.True(t, found, "expected a tail-truncation finding, got %+v", result.Findings)
}

// TestScanInteriorRootGapIsLocalizedFinding builds a 4-root chain
// (root-0..root-3) and then removes the interior root-1 from the fake
// anchor's enumerated window -- an actual element removal, not a
// covered_range/field mutation like the other gap-flavored tests above. This
// is the shape a corrupted/omitted discovery-index row would produce in
// production (see s-5910 for the immudb-specific bookkeeping-gap case).
//
// scan.go's chain/contiguity walk only ever compares the current root to
// prev -- the previously ENUMERATED root, not the previous notary_ts-adjacent
// one -- so when root-1 goes missing, root-2 (the root immediately after the
// gap) is compared against root-0 and must localize the seam there, while
// root-0 (before the gap) and root-3 (safely past the seam, correctly
// chained to root-2) must both stay clean.
func TestScanInteriorRootGapIsLocalizedFinding(t *testing.T) {
	kp := genTestKeyPair(t)
	anchor := newFakeAnchorClient()
	ns := newFakeNotaryServer(t)

	b0 := buildBatch(t, kp, 0, 1, 0, 3, 1000, nil, nil)
	rootHash0, _ := getString(b0.root, "root_hash_b64")
	b1 := buildBatch(t, kp, 0, 1, 3, 2, 2000, "root-0", rootHash0)
	rootHash1, _ := getString(b1.root, "root_hash_b64")
	b2 := buildBatch(t, kp, 0, 1, 5, 2, 3000, "root-1", rootHash1)
	rootHash2, _ := getString(b2.root, "root_hash_b64")
	b3 := buildBatch(t, kp, 0, 1, 7, 2, 4000, "root-2", rootHash2)

	// root-1 is deliberately omitted -- an interior element removal, not a
	// field mutation on a root that's still present.
	anchor.windows[0] = []EnumeratedRoot{
		{RootID: "root-0", Payload: b0.root},
		{RootID: "root-2", Payload: b2.root},
		{RootID: "root-3", Payload: b3.root},
	}
	anchor.heads[0] = &AnchorPointer{RootID: "root-3", ToSeq: 8}

	ns.leaves["root-0"] = b0.leaves
	ns.leaves["root-2"] = b2.leaves
	ns.leaves["root-3"] = b3.leaves

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
	assert.Equal(t, 3, result.RootsWalked, "root-1 was never enumerated -- only 3 roots walked")

	// The gap trips both the chain-link and contiguity checks (each compares
	// independently against prev, the previously ENUMERATED root), so exactly
	// two findings are expected, both localized to root-2 -- the root
	// immediately after the seam. A regression that swallows the seam
	// finding, or that lets it cascade past root-2 onto root-3, would change
	// this count or this localization.
	require.Len(t, result.Findings, 2, "expected exactly a chain and a contiguity finding localized to the seam, got %+v", result.Findings)
	kinds := make(map[string]bool, len(result.Findings))
	for _, f := range result.Findings {
		kinds[f.Kind] = true
		assert.Equal(t, "root-2", f.RootID,
			"the gap must localize to the root immediately after the seam, got %+v", f)
		assert.Equal(t, 0, f.Partition)
	}
	assert.True(t, kinds["chain"], "expected a chain finding, got %+v", result.Findings)
	assert.True(t, kinds["contiguity"], "expected a contiguity finding, got %+v", result.Findings)
}

// setupTwoPartitions builds partition 0's batch chain with partition_count=2
// signed in from the start (mutating partition_count after signing would
// itself invalidate the signature, which is not what these tests are
// about), leaving partition 1 for the caller to populate (or not).
func setupTwoPartitions(t *testing.T) (testKeyPair, *fakeAnchorClient, *fakeNotaryServer) {
	t.Helper()
	kp := genTestKeyPair(t)
	anchor := newFakeAnchorClient()
	ns := newFakeNotaryServer(t)

	b1 := buildBatch(t, kp, 0, 2, 0, 3, 1000, nil, nil)
	rootHash1, _ := getString(b1.root, "root_hash_b64")
	b2 := buildBatch(t, kp, 0, 2, 3, 2, 2000, "root-0", rootHash1)

	anchor.windows[0] = []EnumeratedRoot{
		{RootID: "root-0", Payload: b1.root},
		{RootID: "root-1", Payload: b2.root},
	}
	anchor.heads[0] = &AnchorPointer{RootID: "root-1", ToSeq: 4}
	ns.leaves["root-0"] = b1.leaves
	ns.leaves["root-1"] = b2.leaves

	return kp, anchor, ns
}

func TestScanClosedHistoricalWindowWithLaterHeadIsNotTailTruncation(t *testing.T) {
	kp, anchor, ns := setupClean(t)
	// The partition kept sealing roots after this window's ToTS=10000 --
	// the anchor-head is a LATER root OUTSIDE the scanned window, not a
	// withheld one. Before s-8snm decision 2, ToSeq alone couldn't tell this
	// apart from a genuine tail-truncation and always flagged it, making the
	// scan unusable on any closed historical window (finding F2).
	anchor.heads[0] = &AnchorPointer{RootID: "root-99", ToSeq: 99, NotaryTsTo: 50000}

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	for _, f := range result.Findings {
		assert.NotEqual(t, "tail-truncation", f.Kind,
			"a head outside the scanned window must not be flagged as tail-truncation")
	}
	require.Len(t, result.Partitions, 1)
	assert.True(t, result.Partitions[0].HeadOutsideWindow,
		"partition summary should note the head fell outside the scanned window")
}

func TestScanHeadInsideWindowStillCatchesTailTruncation(t *testing.T) {
	kp, anchor, ns := setupClean(t)
	// The head's own notary_ts_to (5000) IS inside [0, 10000) -- the tail
	// check must still be verdict-bearing here and catch the withheld roots,
	// distinguishing this from the "outside the window" case above.
	anchor.heads[0] = &AnchorPointer{RootID: "root-99", ToSeq: 99, NotaryTsTo: 5000}

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
	found := false
	for _, f := range result.Findings {
		if f.Kind == "tail-truncation" {
			found = true
		}
	}
	assert.True(t, found, "expected a tail-truncation finding, got %+v", result.Findings)
	require.Len(t, result.Partitions, 1)
	assert.False(t, result.Partitions[0].HeadOutsideWindow)
}

func TestScanIdlePartitionIsNotAFinding(t *testing.T) {
	kp, anchor, ns := setupTwoPartitions(t)
	// Partition 1 has a head whose own notary_ts_to (100) falls BEFORE this
	// scan's FromTS (500) -- genuinely idle since before the window opened,
	// not a drop. (Distinct from a head whose notary_ts_to falls INSIDE the
	// window with zero roots enumerated, which is a whole-window wipe -- see
	// TestScanWholeWindowWipeWithHeadInsideWindowIsFinding below.)
	anchor.heads[1] = &AnchorPointer{RootID: "root-idle", ToSeq: 0, NotaryTsTo: 100}

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0, 1}, FromTS: 500, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	for _, ps := range result.Partitions {
		if ps.Partition == 1 {
			assert.True(t, ps.Idle)
		}
	}
}

// TestScanIdlePartitionWithHeadAfterWindowIsNotAFinding is the symmetric
// case: a head that outlived this window (sealed after ToTS closed) is
// still idle *within* this window, not a drop -- the other side of the
// window boundary from TestScanIdlePartitionIsNotAFinding above.
func TestScanIdlePartitionWithHeadAfterWindowIsNotAFinding(t *testing.T) {
	kp, anchor, ns := setupTwoPartitions(t)
	anchor.heads[1] = &AnchorPointer{RootID: "root-later", ToSeq: 9, NotaryTsTo: 50000}

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0, 1}, FromTS: 500, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	for _, ps := range result.Partitions {
		if ps.Partition == 1 {
			assert.True(t, ps.Idle)
		}
	}
}

// TestScanWholeWindowWipeWithHeadInsideWindowIsFinding is the direct
// regression for the "idle vs. whole-window wipe" gap: partition 1's own
// anchor-head reports notary_ts_to=5000, squarely inside this scan's
// [500, 10000) window -- proving a root WAS anchored here -- yet zero roots
// are enumerated for it. Before this fix, step 6 treated any non-nil head as
// sufficient for "idle" regardless of where its timestamp fell, so this
// exact scenario (every root inside the window silently wiped from the
// anchor, while the stale head pointer was left untouched) produced no
// finding and a clean exit code.
func TestScanWholeWindowWipeWithHeadInsideWindowIsFinding(t *testing.T) {
	kp, anchor, ns := setupTwoPartitions(t)
	anchor.heads[1] = &AnchorPointer{RootID: "root-wiped", ToSeq: 7, NotaryTsTo: 5000}

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0, 1}, FromTS: 500, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
	found := false
	for _, f := range result.Findings {
		if f.Kind == "partition-coverage" && f.Partition == 1 {
			found = true
			assert.Contains(t, f.Detail, "whole-window wipe")
		}
	}
	assert.True(t, found, "expected a partition-coverage finding for partition 1's whole-window wipe, got %+v", result.Findings)
	for _, ps := range result.Partitions {
		if ps.Partition == 1 {
			// The Idle summary flag (zero roots + head present) is still
			// set -- it's the finding, not this flag, that carries the
			// wipe signal; the flag alone was the source of the bug.
			assert.True(t, ps.Idle)
		}
	}
}

func TestScanWholePartitionDropIsFinding(t *testing.T) {
	kp, anchor, ns := setupTwoPartitions(t)
	// Partition 1: no head, no roots -- a whole-partition drop.

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0, 1}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
	found := false
	for _, f := range result.Findings {
		if f.Kind == "partition-coverage" && f.Partition == 1 {
			found = true
		}
	}
	assert.True(t, found, "expected a partition-coverage finding for partition 1, got %+v", result.Findings)
}

func TestScanBatchDensityMismatchIsFinding(t *testing.T) {
	kp, anchor, ns := setupClean(t)
	// Delete a leaf from the notary-leaf index only (root-0's leaf set) --
	// the interior-leaf-index-deletion attack finding 1 describes.
	ns.leaves["root-0"] = ns.leaves["root-0"][:len(ns.leaves["root-0"])-1]

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
	var f *Finding
	for i := range result.Findings {
		if result.Findings[i].Kind == "batch-density" {
			f = &result.Findings[i]
		}
	}
	require.NotNil(t, f, "expected a batch-density finding, got %+v", result.Findings)
	assert.Equal(t, "root-0", f.RootID)
}

func TestScanRecordExistenceMissingIsFinding(t *testing.T) {
	kp, anchor, ns := setupClean(t)
	missingID := ns.leaves["root-0"][1].ID
	authAbsent := false
	ns.existence[missingID] = RecordExistenceRow{ID: missingID, Found: false, AuthorizedAbsent: &authAbsent}

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
	var f *Finding
	for i := range result.Findings {
		if result.Findings[i].Kind == "record-existence" {
			f = &result.Findings[i]
		}
	}
	require.NotNil(t, f, "expected a record-existence finding, got %+v", result.Findings)
	assert.Equal(t, missingID, f.RecordID)
	require.NotNil(t, f.Offset)
	require.NotNil(t, f.LeafIndex)
	assert.Equal(t, int64(1), *f.LeafIndex)
}

func TestScanRecordExistenceAuthorizedAbsentIsNotAFinding(t *testing.T) {
	kp, anchor, ns := setupClean(t)
	missingID := ns.leaves["root-0"][1].ID
	authAbsent := true
	ns.existence[missingID] = RecordExistenceRow{ID: missingID, Found: false, AuthorizedAbsent: &authAbsent}

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode, "ILM-expected absence must not read as a finding")
	assert.Empty(t, result.Findings)
}

func TestScanRecordExistenceUndeterminedFailsClosed(t *testing.T) {
	kp, anchor, ns := setupClean(t)
	missingID := ns.leaves["root-0"][1].ID
	ns.existence[missingID] = RecordExistenceRow{ID: missingID, Found: false, AuthorizedAbsent: nil}

	result, err := Scan(context.Background(), Config{
		Partitions: []int{0}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode, "an undetermined authorized-absence must fail closed, not pass silently")
}

func TestScanEnumerateErrorAborts(t *testing.T) {
	kp, anchor, ns := setupClean(t)
	anchor.enumerateErr[0] = assert.AnError

	_, err := Scan(context.Background(), Config{
		Partitions: []int{0}, FromTS: 0, ToTS: 10000,
		Anchor: anchor, Notary: ns.client(), NotaryPubKey: kp.pub,
	})
	assert.Error(t, err, "an anchor infrastructure failure must abort the scan, never silently read as a clean/empty window")
}
