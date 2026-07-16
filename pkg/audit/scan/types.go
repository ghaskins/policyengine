//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import "context"

// SignedRoot is a decoded signed-root payload as fetched directly from an
// anchor backend: the 10-field signable allowlist (root_hash_b64, tree_size,
// partition, partition_count, covered_range, prev_root_hash_b64, prev_root_id,
// notary_ts_from, notary_ts_to, retention_policy) plus the three fields
// sign-and-assemble merges in afterward (root_signature_b64, root_key_id,
// root_pub_key_b64) -- see mpe-iam-lite's notary/canonical.clj
// (signable-root-fields) and docs/notary/data-structures.md §4. Decoded with
// json.Number for integers throughout, so it interoperates directly with
// pkg/audit/verify's exported canonical-JSON/signature helpers.
type SignedRoot = map[string]interface{}

// AnchorPointer is a partition's latest known root, per AnchorStore's
// anchor-head (mpe-iam-lite notary/anchor/api.clj).
type AnchorPointer struct {
	RootID string
	ToSeq  int64
	// NotaryTsTo is the head root's own signed notary_ts_to (s-8snm decision
	// 2) -- distinct from ToSeq, the Kafka covered_range sequence position.
	// Scan step 5's tail check needs both: ToSeq alone can't distinguish "the
	// head is a later root outside the scanned window" (benign) from "roots
	// were withheld from inside it" (tamper) -- both look identical as
	// head.ToSeq > lastEnumerated.ToSeq. Comparing NotaryTsTo against the
	// window's toTS resolves the ambiguity: the tail check is only
	// verdict-bearing when NotaryTsTo falls inside [fromTS, toTS). Zero for a
	// pointer written before this field existed on the iam-lite side; a zero
	// value only ever makes the tail check MORE cautious (treats the head as
	// inside the window when it might not be), never less.
	NotaryTsTo int64
}

// EnumeratedRoot is one root returned by EnumerateRootsInWindow: its
// backend-assigned root-id (the key immudb's HTree / S3's WORM object anchors
// it under) and its decoded signed-root payload.
type EnumeratedRoot struct {
	RootID  string
	Payload SignedRoot
}

// AnchorProofResult is the outcome of verifying one root's own
// anchor-inclusion proof (scan step 3) -- the same depth pkg/audit/verify
// applies to a bundle's anchor_refs, but recomputed directly from a live
// anchor fetch rather than trusted from a bundle's self-reported ref.
type AnchorProofResult struct {
	OK     bool
	Detail string
}

// AnchorClient abstracts one anchor tier (immudb, S3, and additively in the
// future an independent witness -- s-3vlq decision 9). Every method mirrors
// mpe-iam-lite's AnchorStore protocol (notary/anchor/api.clj) one-for-one,
// so the scan algorithm's own logic (contiguity, tail, coverage) is
// backend-agnostic; only the wire protocol to reach the anchor differs.
type AnchorClient interface {
	// Tier is a short, human-readable label for this anchor's guarantee
	// level (e.g. "immudb:cryptographic-tamper-evidence",
	// "s3:provider-trusted-worm") -- deliberately an open string, not an
	// enum, so a future witness tier is additive (s-3vlq decision 9).
	Tier() string

	// AnchorHead returns partition's latest known root, or nil if the
	// partition has never anchored a root. MUST return the pointer's
	// documented staleness bound as-is (it may lag the true latest root by
	// one in-flight append-root! -- see anchor/api.clj) -- callers must
	// tolerate "enumerated > head" as ordinary lag, never as tampering;
	// only "enumerated < head" is the genuine withholding signal.
	AnchorHead(ctx context.Context, partition int) (*AnchorPointer, error)

	// EnumerateRootsInWindow returns every root anchored under partition
	// whose notary_ts_to falls in [fromTS, toTS), ordered ascending by
	// notary_ts_to. MUST throw/return an error rather than silently
	// returning a truncated or empty result on an infrastructure failure --
	// the caller cannot otherwise distinguish a genuinely empty window from
	// a masked read failure (anchor/api.clj's documented contract).
	EnumerateRootsInWindow(ctx context.Context, partition int, fromTS, toTS int64) ([]EnumeratedRoot, error)

	// VerifyAnchorProof cryptographically validates root's own
	// anchor-inclusion proof: immudb's 4-part inclusion/state-signature/
	// ALH-binding/entry-hash-binding check, or S3's WORM object-lock +
	// server-computed content checksum binding. pubKey is the anchor's own
	// out-of-band trust root (immudb server signing key; unused for S3).
	VerifyAnchorProof(ctx context.Context, root EnumeratedRoot, pubKey interface{}) (AnchorProofResult, error)

	// AnchorRef fetches and assembles the anchor_refs-shaped map
	// (e.g. {"immudb": {...}} or {"s3": {...}}) for root -- the same
	// material VerifyAnchorProof cryptographically checks, exposed so a
	// counter-example bundle can carry genuine, independently
	// re-verifiable proof material rather than a bare re-assertion.
	AnchorRef(ctx context.Context, root EnumeratedRoot) (map[string]interface{}, error)
}

// LeafRow is one row from GET /api/v1/notary/leaves?root_id=<id> -- the
// ordered leaf set sealed under one batch root (scan step 7).
type LeafRow struct {
	ID          string
	Seq         int64
	LeafIndex   int64
	LeafHashB64 string
}

// RecordExistenceRow is one row from POST /api/v1/notary/record-existence --
// per-id presence in the accesslog index, retention-floor-aware (scan step 8).
type RecordExistenceRow struct {
	ID string
	// Found is true when the record is genuinely present in accesslog, with
	// LeafHashB64/SignatureB64 populated from its integrity envelope.
	Found        bool
	LeafHashB64  string
	SignatureB64 string
	// AuthorizedAbsent is nil when Found is true, or when absence could not
	// be evaluated (record was never sealed into the leaf-index at all, or
	// its covering root's retention_policy failed to parse) -- callers must
	// treat nil as "cannot be determined", never as authorized. Non-nil:
	// true means ILM-expected absence (not a tamper signal), false means
	// still inside the retention window (a genuine tamper signal).
	AuthorizedAbsent *bool
}

// Finding is one discrepancy the scan surfaced, with enough context to build
// a counter-example bundle (BuildCounterExampleBundle) for a "batch-density"
// or "record-existence" finding.
type Finding struct {
	// Kind is one of: "root-signature", "chain", "anchor-proof",
	// "contiguity", "tail-truncation", "partition-coverage",
	// "batch-density", "record-existence".
	Kind      string
	Partition int
	RootID    string
	// Offset and LeafIndex are populated for a batch-density/record-existence
	// finding -- the pinpointed (partition, offset, leaf_index, root_id)
	// counter-example (s-3vlq decision 7).
	Offset    *int64
	LeafIndex *int64
	RecordID  string
	Detail    string
}

// PartitionSummary is one partition's scan tally, rolled up into Result.
type PartitionSummary struct {
	Partition      int
	RootsWalked    int
	LeavesCensused int
	// Idle is true when the partition had a partition_count seam
	// (partition < some root's partition_count) but zero roots enumerated in
	// the window -- an idle partition, not a drop (scan step 6).
	Idle bool
	// HeadOutsideWindow is true when this partition's anchor-head falls
	// outside [FromTS, ToTS) -- s-8snm decision 2's scope note, not a
	// finding. It means scan step 5's tail check could not be evaluated for
	// this window: the anchor has advanced (or was checked) past the
	// window's own close, which is expected for anything but the
	// live-growing tail, not a withholding signal.
	HeadOutsideWindow bool
}

// Result is the outcome of Scan.
type Result struct {
	// ExitCode mirrors pkg/audit/verify's convention: 0 = clean scan, 2 =
	// one or more discrepancies found. There is no "tampered but exit 1"
	// tier here -- unlike a single bundle, a completeness scan either found
	// a genuine gap or it didn't.
	ExitCode         int
	PartitionsWalked int
	RootsWalked      int
	LeavesCensused   int
	// VerdictTier summarizes which anchor tier(s) backed this scan (e.g.
	// "immudb:cryptographic-tamper-evidence") -- deliberately open-ended,
	// mirroring AnchorClient.Tier (s-3vlq decision 9).
	VerdictTier string
	Partitions  []PartitionSummary
	// Findings is empty on a clean scan. Non-empty means ExitCode == 2.
	Findings []Finding
}
