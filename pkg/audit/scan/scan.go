//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"golang.org/x/sync/errgroup"

	"github.com/manetu/policyengine/pkg/audit/verify"
)

// Config carries everything one Scan call needs: which partitions to walk,
// the notary_ts window, the anchor and iam-lite clients, and the out-of-band
// trust roots.
type Config struct {
	// Partitions is the explicit set of partition indices to scan --
	// normally 0..currentPartitionCount-1, resolved by the caller (e.g. by
	// probing AnchorHead across a small initial range, or from operator
	// configuration). Step 6's partition_count coverage check is only ever
	// evaluated within this requested set.
	Partitions []int
	FromTS     int64
	ToTS       int64
	Anchor     AnchorClient
	Notary     *NotaryClient
	// NotaryPubKey is the notary's own signing key (Ed25519/ECDSA P-256),
	// obtained out-of-band -- never trusted from a live endpoint alone. Used
	// for root-signature verification (steps 2/5).
	NotaryPubKey interface{}
	// AnchorPubKey is the anchor tier's own out-of-band trust root (the
	// immudb server's signing key); unused for the S3 tier, whose binding is
	// a pure function of the object's own bytes.
	AnchorPubKey interface{}
	// TrustedNowMs is the verifier's trusted wall-clock (epoch-ms), used for
	// step 8's retention-floor evaluation. Must not be read from anywhere
	// anchor- or service-controlled.
	TrustedNowMs int64
	// Concurrency bounds how many partitions are scanned at once (mirroring
	// bundle.clj's fetch-window-partitions! fan-out). Defaults to
	// len(Partitions) when <= 0.
	Concurrency int
	// RecordExistenceBatchSize bounds how many ids are sent per
	// record-existence request. Defaults to 500 when <= 0.
	RecordExistenceBatchSize int
}

func coveredRange(payload SignedRoot) (fromSeq, toSeq int64, ok bool) {
	cr, exists := getMap(payload, "covered_range")
	if !exists {
		return 0, 0, false
	}
	from, ok1 := getInt64(cr, "from_seq")
	to, ok2 := getInt64(cr, "to_seq")
	return from, to, ok1 && ok2
}

func isHeartbeat(payload SignedRoot) bool {
	ts, ok := getInt64(payload, "tree_size")
	return ok && ts == 0
}

// partitionScan holds one partition's scan outcome, feeding both that
// partition's own findings and the cross-partition step-6 coverage check.
type partitionScan struct {
	partition         int
	roots             []EnumeratedRoot
	head              *AnchorPointer
	maxPartCount      int64
	findings          []Finding
	leavesCensused    int
	headOutsideWindow bool
}

func scanOnePartition(ctx context.Context, cfg Config, partition int) (partitionScan, error) {
	ps := partitionScan{partition: partition}

	roots, err := cfg.Anchor.EnumerateRootsInWindow(ctx, partition, cfg.FromTS, cfg.ToTS)
	if err != nil {
		return ps, fmt.Errorf("scan: partition %d: enumerate-roots-in-window failed: %w", partition, err)
	}
	sort.SliceStable(roots, func(i, j int) bool {
		ai, _ := getInt64(roots[i].Payload, "notary_ts_to")
		aj, _ := getInt64(roots[j].Payload, "notary_ts_to")
		return ai < aj
	})
	ps.roots = roots

	head, err := cfg.Anchor.AnchorHead(ctx, partition)
	if err != nil {
		return ps, fmt.Errorf("scan: partition %d: anchor-head failed: %w", partition, err)
	}
	ps.head = head

	var prev *EnumeratedRoot
	for i := range roots {
		root := roots[i]
		if pc, ok := getInt64(root.Payload, "partition_count"); ok && pc > ps.maxPartCount {
			ps.maxPartCount = pc
		}

		// Step 2a: root signature.
		if !verify.VerifyRootSignature(root.Payload, cfg.NotaryPubKey) {
			ps.findings = append(ps.findings, Finding{
				Kind: "root-signature", Partition: partition, RootID: root.RootID,
				Detail: "root signature verification failed",
			})
		}

		// Step 2b: chain link to predecessor (within this enumerated
		// window). The very first enumerated root's own prev_root_id may
		// point outside the window -- that boundary is a caveat, not a
		// failure, mirroring pkg/audit/verify's ChainCaveat for a
		// non-embedded predecessor (walking arbitrarily far back is the
		// job of a wider/earlier scan, not this bounded window).
		if prev != nil {
			prevHash, _ := getString(prev.Payload, "root_hash_b64")
			curPrevHash, _ := getString(root.Payload, "prev_root_hash_b64")
			curPrevID, _ := getString(root.Payload, "prev_root_id")
			if curPrevID != prev.RootID || curPrevHash == "" || curPrevHash != prevHash {
				ps.findings = append(ps.findings, Finding{
					Kind: "chain", Partition: partition, RootID: root.RootID,
					Detail: fmt.Sprintf("chain link to predecessor %q broken", prev.RootID),
				})
			}
		}

		// Step 3: anchor-inclusion proof, at the same depth as the offline
		// per-record verifier.
		proof, err := cfg.Anchor.VerifyAnchorProof(ctx, root, cfg.AnchorPubKey)
		if err != nil {
			return ps, fmt.Errorf("scan: partition %d: verify-anchor-proof failed for root %q: %w", partition, root.RootID, err)
		}
		if !proof.OK {
			ps.findings = append(ps.findings, Finding{
				Kind: "anchor-proof", Partition: partition, RootID: root.RootID,
				Detail: proof.Detail,
			})
		}

		// Step 4: offset contiguity, with the heartbeat degenerate-range
		// exception.
		if prev != nil {
			_, prevTo, prevOK := coveredRange(prev.Payload)
			curFrom, curTo, curOK := coveredRange(root.Payload)
			if prevOK && curOK {
				switch {
				case isHeartbeat(root.Payload):
					if curFrom != prevTo || curTo != prevTo {
						ps.findings = append(ps.findings, Finding{
							Kind: "contiguity", Partition: partition, RootID: root.RootID,
							Detail: fmt.Sprintf("heartbeat root's covered_range {%d,%d} does not degenerately re-assert predecessor's to_seq %d", curFrom, curTo, prevTo),
						})
					}
				default:
					if curFrom != prevTo+1 {
						ps.findings = append(ps.findings, Finding{
							Kind: "contiguity", Partition: partition, RootID: root.RootID,
							Detail: fmt.Sprintf("gap: predecessor covered_range.to_seq=%d, this root's covered_range.from_seq=%d", prevTo, curFrom),
						})
					}
				}
			}
		}

		rootCopy := root
		prev = &rootCopy
	}

	// Step 5: tail check against the anchor's own head -- verdict-bearing
	// only when the head falls inside the scanned window (s-8snm decision
	// 2). ToSeq alone can't distinguish "the head is a later root outside
	// this window" (benign -- e.g. auditing a closed historical period while
	// the partition has kept sealing since) from "roots were withheld from
	// inside it" (tamper): both look identical as head.ToSeq >
	// lastEnumerated.ToSeq. NotaryTsTo resolves the ambiguity: only when the
	// head's own notary_ts_to is still within [FromTS, ToTS) must the last
	// enumerated root actually BE the head.
	if len(roots) > 0 && head != nil {
		last := roots[len(roots)-1]
		_, lastToSeq, ok := coveredRange(last.Payload)
		switch {
		case head.NotaryTsTo >= cfg.ToTS:
			// The head is outside this window -- nothing about the tail is
			// verdict-bearing here. Not a finding: a scope note only.
			ps.headOutsideWindow = true
		case ok && lastToSeq < head.ToSeq:
			ps.findings = append(ps.findings, Finding{
				Kind: "tail-truncation", Partition: partition, RootID: last.RootID,
				Detail: fmt.Sprintf("last enumerated root covers up to seq %d, but anchor-head reports seq %d -- roots were withheld", lastToSeq, head.ToSeq),
			})
		}
	}

	// Steps 7-8: batch density + record existence, per non-heartbeat root.
	batchSize := cfg.RecordExistenceBatchSize
	if batchSize <= 0 {
		batchSize = 500
	}
	for _, root := range roots {
		if isHeartbeat(root.Payload) {
			continue
		}
		leaves, err := cfg.Notary.Leaves(ctx, root.RootID)
		if err != nil {
			return ps, fmt.Errorf("scan: partition %d: leaves fetch failed for root %q: %w", partition, root.RootID, err)
		}
		ps.leavesCensused += len(leaves)

		notaryTsTo, _ := getInt64(root.Payload, "notary_ts_to")
		recomputed, err := recomputeBatchRoot(partition, notaryTsTo, leaves)
		expectedRootHashB64, _ := getString(root.Payload, "root_hash_b64")
		expectedRootHash, decodeErr := b64urlDecode(expectedRootHashB64)
		densityOK := err == nil && decodeErr == nil && bytes.Equal(recomputed, expectedRootHash)
		if !densityOK {
			detail := "recomputed Merkle root from /leaves does not match the anchor-fetched root_hash_b64 -- a leaf was deleted from or added to the leaf-index"
			if err != nil {
				detail = "batch density recompute failed: " + err.Error()
			}
			ps.findings = append(ps.findings, Finding{
				Kind: "batch-density", Partition: partition, RootID: root.RootID,
				Detail: detail,
			})
			continue // step 8 is meaningless against a leaf set we already know is wrong
		}

		if len(leaves) == 0 {
			continue
		}
		ids := make([]string, len(leaves))
		bySeq := make(map[string]LeafRow, len(leaves))
		for i, l := range leaves {
			ids[i] = l.ID
			bySeq[l.ID] = l
		}
		for start := 0; start < len(ids); start += batchSize {
			end := start + batchSize
			if end > len(ids) {
				end = len(ids)
			}
			rows, err := cfg.Notary.RecordExistence(ctx, ids[start:end])
			if err != nil {
				return ps, fmt.Errorf("scan: partition %d: record-existence fetch failed for root %q: %w", partition, root.RootID, err)
			}
			for _, row := range rows {
				if row.Found {
					continue
				}
				if row.AuthorizedAbsent != nil && *row.AuthorizedAbsent {
					continue // ILM-expected absence, not a tamper signal
				}
				leaf := bySeq[row.ID]
				offset := leaf.Seq
				leafIndex := leaf.LeafIndex
				detail := "record is absent from accesslog but still inside the retention window"
				if row.AuthorizedAbsent == nil {
					detail = "record is absent from accesslog and its authorized-absence could not be determined (never sealed into the leaf-index, or its root's retention_policy failed to parse) -- fails closed"
				}
				ps.findings = append(ps.findings, Finding{
					Kind: "record-existence", Partition: partition, RootID: root.RootID,
					Offset: &offset, LeafIndex: &leafIndex, RecordID: row.ID,
					Detail: detail,
				})
			}
		}
	}

	return ps, nil
}

// Scan runs the completeness scan across cfg.Partitions for the notary_ts
// window [cfg.FromTS, cfg.ToTS).
func Scan(ctx context.Context, cfg Config) (Result, error) {
	if len(cfg.Partitions) == 0 {
		return Result{}, fmt.Errorf("scan: no partitions requested")
	}
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = len(cfg.Partitions)
	}

	results := make([]partitionScan, len(cfg.Partitions))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i, p := range cfg.Partitions {
		i, p := i, p
		g.Go(func() error {
			ps, err := scanOnePartition(gctx, cfg, p)
			if err != nil {
				return err
			}
			results[i] = ps
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return Result{}, err
	}

	byPartition := make(map[int]partitionScan, len(results))
	var maxPartCount int64
	for _, ps := range results {
		byPartition[ps.partition] = ps
		if ps.maxPartCount > maxPartCount {
			maxPartCount = ps.maxPartCount
		}
	}

	requested := make(map[int]bool, len(cfg.Partitions))
	for _, p := range cfg.Partitions {
		requested[p] = true
	}

	var (
		findings       []Finding
		partitionsOut  []PartitionSummary
		rootsWalked    int
		leavesCensused int
	)

	for _, ps := range results {
		findings = append(findings, ps.findings...)
		rootsWalked += len(ps.roots)
		leavesCensused += ps.leavesCensused
		partitionsOut = append(partitionsOut, PartitionSummary{
			Partition:         ps.partition,
			RootsWalked:       len(ps.roots),
			LeavesCensused:    ps.leavesCensused,
			Idle:              len(ps.roots) == 0 && ps.head != nil,
			HeadOutsideWindow: ps.headOutsideWindow,
		})
	}

	// Step 6: partition_count coverage. Only evaluated within the requested
	// partition set -- a partition never asked for is out of scope, not a
	// finding.
	for p := int64(0); p < maxPartCount; p++ {
		pi := int(p)
		if !requested[pi] {
			continue
		}
		ps, ok := byPartition[pi]
		if !ok || len(ps.roots) > 0 {
			continue
		}
		// A head whose own notary_ts_to falls INSIDE [FromTS, ToTS) is not
		// idle -- it proves a root WAS anchored in this exact window, and
		// EnumerateRootsInWindow just returned zero for it: a whole-window
		// wipe, not idle (mirrors step 5's own NotaryTsTo-based tail-check
		// reasoning, which only runs when len(roots) > 0 and so can't cover
		// this all-roots-missing case). Only a head genuinely outside the
		// window -- or no head at all -- is idle/out of scope here.
		if ps.head != nil && (ps.head.NotaryTsTo < cfg.FromTS || ps.head.NotaryTsTo >= cfg.ToTS) {
			continue // idle, not a drop -- anchor-head proves this partition has anchored, but not inside this window
		}
		detail := fmt.Sprintf("partition %d has zero roots in-window and no anchor-head at all, while partition_count=%d is attested by other roots in this scan -- whole-partition drop (or a partition added so recently it has not yet sealed its first root; see s-3vlq's documented partition_count staleness bound)", pi, maxPartCount)
		if ps.head != nil {
			detail = fmt.Sprintf("partition %d has zero roots in-window, but its own anchor-head (root_id=%s) reports notary_ts_to=%d inside the requested window [%d,%d) -- a root WAS anchored here and is now missing from enumeration: whole-window wipe", pi, ps.head.RootID, ps.head.NotaryTsTo, cfg.FromTS, cfg.ToTS)
		}
		findings = append(findings, Finding{
			Kind: "partition-coverage", Partition: pi,
			Detail: detail,
		})
	}

	result := Result{
		PartitionsWalked: len(cfg.Partitions),
		RootsWalked:      rootsWalked,
		LeavesCensused:   leavesCensused,
		VerdictTier:      cfg.Anchor.Tier(),
		Partitions:       partitionsOut,
		Findings:         findings,
	}
	if len(findings) > 0 {
		result.ExitCode = 2
	}
	return result, nil
}
