//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// bundleMetaType is the required meta.type discriminator for a Manetu audit
// verification bundle. A bundle whose meta.type does not match this value is
// rejected outright, before any cryptographic work, so that feeding the
// verifier the wrong kind of file (a PEM, an anchor object, an unrelated
// JSON document) fails with a clear message instead of a downstream
// missing-field/parse error.
const bundleMetaType = "manetu-audit-verification-bundle"

// supportedSchemaMajor is the MAJOR version this verifier accepts for
// meta.schema_version ("MAJOR.MINOR"). A greater MAJOR is refused (the
// bundle shape may have changed incompatibly); a greater MINOR is accepted
// silently (additive, forward-compatible changes only bump MINOR).
//
// Bumped 1 -> 2 to track the reference Clojure implementation's own schema-2
// migration: major 2 dropped the set-bundle completeness/root_chain_context
// fields (a breaking change, per project convention of no back-compat
// shims, so a pre-2.0 bundle is correctly refused rather than silently
// accepted) and replaced the retired timestamp_ms signable-root field with
// the current notary_ts_from/notary_ts_to/partition_count set (see
// SignableRootFields).
const supportedSchemaMajor = "2"

// IntegrityStatus is the per-record outcome of [VerifyRecordIntegrity].
type IntegrityStatus string

// Possible per-record integrity outcomes.
const (
	StatusVerified            IntegrityStatus = "verified"
	StatusTampered            IntegrityStatus = "tampered"
	StatusUnverifiedNotSealed IntegrityStatus = "unverified-not-sealed"
)

// IntegrityResult is the outcome of [VerifyRecordIntegrity].
type IntegrityResult struct {
	Status IntegrityStatus
	Detail string
}

// VerifyRecordIntegrity is Steps 1-2: per-record leaf-hash recomputation
// (SHA-256 over the raw record protobuf bytes) and Ed25519/ECDSA signature
// verification over that leaf hash.
func VerifyRecordIntegrity(record map[string]interface{}, pubKey interface{}) IntegrityResult {
	if record == nil {
		return IntegrityResult{StatusUnverifiedNotSealed, "no record data in bundle"}
	}
	integrity, ok := getMap(record, "integrity")
	if !ok {
		return IntegrityResult{StatusUnverifiedNotSealed, "no integrity field (pre-enablement record)"}
	}
	recordPBB64, hasPB := getString(record, "record_pb_b64")
	leafHashB64, hasLH := getString(integrity, "leaf_hash_b64")
	sigB64, hasSig := getString(integrity, "signature_b64")
	if !hasPB || !hasLH || !hasSig {
		return IntegrityResult{StatusTampered, "integrity map present but sub-fields stripped"}
	}
	pbBytes, err := b64Decode(recordPBB64)
	if err != nil {
		return IntegrityResult{StatusTampered, "malformed record_pb_b64: base64 decode failed"}
	}
	expectedLH, err := b64Decode(leafHashB64)
	if err != nil {
		return IntegrityResult{StatusTampered, "malformed leaf_hash_b64: base64 decode failed"}
	}
	computedLH := LeafHash(pbBytes)
	if !bytes.Equal(computedLH, expectedLH) {
		return IntegrityResult{StatusTampered, "leaf hash mismatch: record_pb has been modified"}
	}
	sigBytes, err := b64Decode(sigB64)
	if err != nil {
		return IntegrityResult{StatusTampered, "malformed signature_b64: base64 decode failed"}
	}
	if VerifySignature(pubKey, expectedLH, sigBytes) {
		return IntegrityResult{StatusVerified, "leaf hash and signature verified"}
	}
	return IntegrityResult{StatusTampered, "signature verification failed"}
}

// bundleAuditPath converts a bundle's merkle_proof.audit_path
// ([{hash_b64, side}]) into ProofSteps.
func bundleAuditPath(auditPath []interface{}) ([]ProofStep, error) {
	steps := make([]ProofStep, 0, len(auditPath))
	for _, raw := range auditPath {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, errors.New("verify: invalid audit-path entry")
		}
		hashB64, _ := getString(m, "hash_b64")
		sideStr, _ := getString(m, "side")
		h, err := b64Decode(hashB64)
		if err != nil {
			return nil, err
		}
		var side Side
		switch sideStr {
		case "left":
			side = SideLeft
		case "right":
			side = SideRight
		default:
			return nil, fmt.Errorf("verify: invalid audit-path side %q", sideStr)
		}
		steps = append(steps, ProofStep{Hash: h, Side: side})
	}
	return steps, nil
}

// PositionedLeafHash computes the notary's actual Merkle-tree leaf preimage
// (Design D1, mpe-iam-lite s-2lxx decision 4): a record's own per-record
// leaf hash (Steps 1-2's content-only SHA-256) alone is NOT what gets
// hashed into the batch tree -- its tree position (partition, Kafka offset,
// 0-based batch index, and the sealing root's notary_ts_to) is bound in
// first. Binding position into the tree leaf means a deleted, substituted,
// or re-ordered record fails Step 3's inclusion check against the signed
// root even though its own content hash and per-record signature (which
// remain position-independent) still verify standalone.
//
//	sha256(CanonicalJSONBytes({partition, offset, index, notary_ts, content_hash_b64}))
func PositionedLeafHash(partition, offset, index, notaryTs int64, contentHashB64 string) ([]byte, error) {
	payload := map[string]interface{}{
		"partition":        json.Number(strconv.FormatInt(partition, 10)),
		"offset":           json.Number(strconv.FormatInt(offset, 10)),
		"index":            json.Number(strconv.FormatInt(index, 10)),
		"notary_ts":        json.Number(strconv.FormatInt(notaryTs, 10)),
		"content_hash_b64": contentHashB64,
	}
	canonical, err := CanonicalJSONBytes(payload)
	if err != nil {
		return nil, fmt.Errorf("verify: positioned-leaf-hash: canonical JSON encode failed: %w", err)
	}
	h := sha256.Sum256(canonical)
	return h[:], nil
}

// VerifyMerkleInclusion is Step 3: RFC 6962 Merkle inclusion proof
// verification. leafHash is the record's own per-record leaf hash
// (content-only, Steps 1-2); signedRoot and merkleProof are the bundle's
// :signed_root and :merkle_proof maps.
//
// The tree's actual leaf preimage is the *positioned* hash, not leafHash
// itself (see [PositionedLeafHash]): leafHash's tree position --
// signed_root.partition, merkle_proof.offset, merkle_proof.leaf_index, and
// signed_root.notary_ts_to -- is bound in before RFC 6962 hashing. All four
// positioning fields must be present, or this fails closed: a bundle that
// cannot be positioned must never silently fall back to hashing leafHash
// bare, or a deleted/substituted/re-ordered record could pass Step 3
// undetected.
//
// leaf_index is additionally bounds-checked against [0, tree_size) when
// tree_size is present -- a sanity check on these unsigned fields, not
// itself a cryptographic binding: for sparse batches (interior id-dedup
// drops) a covered_range seq-span comparison is not a valid substitute for
// this range check, but inclusion soundness rests entirely on
// VerifyInclusion's fold reproducing the signed root hash, not on this
// bound.
func VerifyMerkleInclusion(leafHash []byte, signedRoot, merkleProof map[string]interface{}) bool {
	rootHashB64, _ := getString(signedRoot, "root_hash_b64")
	rootHash, err := b64Decode(rootHashB64)
	if err != nil {
		return false
	}
	auditPathRaw, _ := getSlice(merkleProof, "audit_path")
	proof, err := bundleAuditPath(auditPathRaw)
	if err != nil {
		return false
	}

	partition, hasPartition := getInt64(signedRoot, "partition")
	offset, hasOffset := getInt64(merkleProof, "offset")
	leafIndex, hasLeafIndex := getInt64(merkleProof, "leaf_index")
	notaryTs, hasNotaryTs := getInt64(signedRoot, "notary_ts_to")
	if !hasPartition || !hasOffset || !hasLeafIndex || !hasNotaryTs {
		return false
	}
	if treeSize, hasTreeSize := getInt64(signedRoot, "tree_size"); hasTreeSize {
		if leafIndex < 0 || leafIndex >= treeSize {
			return false
		}
	}

	positioned, err := PositionedLeafHash(partition, offset, leafIndex, notaryTs, b64urlEncode(leafHash))
	if err != nil {
		return false
	}
	return VerifyInclusion(rootHash, positioned, proof)
}

// SignableRootFields is the exact set of fields covered by a batch/heartbeat
// root's signature -- the single source of truth for reconstructing the
// signable payload. A field NOT in this list (e.g. root_pub_key_b64,
// advisory metadata never covered by the signature) must never be included,
// or the canonical JSON reconstruction will differ from what the signer
// actually signed and the signature check will spuriously fail.
//
// This is the schema-2 field set (10 fields): timestamp_ms was retired in
// favor of notary_ts_from/notary_ts_to (notary_ts_to plays timestamp_ms's
// former role as the root's own seal time -- see the retention-floor checks
// below), and partition_count was added, mirroring the reference Clojure
// implementation's notary/canonical.clj signable-root-fields.
var SignableRootFields = []string{
	"root_hash_b64", "tree_size", "partition", "partition_count", "covered_range",
	"prev_root_hash_b64", "prev_root_id", "notary_ts_from", "notary_ts_to", "retention_policy",
}

func selectKeys(m map[string]interface{}, keys []string) map[string]interface{} {
	out := make(map[string]interface{}, len(keys))
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

// VerifyRootSignature is Step 4: verifies the signed_root payload's
// signature against the canonical JSON of the positive 10-field allowlist
// (SignableRootFields) -- never by stripping the signature fields from the
// map, since a live-fetched root may carry a third, non-signature field
// (root_pub_key_b64) that a naive "everything except the signature" would
// wrongly include.
func VerifyRootSignature(signedRoot map[string]interface{}, pubKey interface{}) bool {
	signable := selectKeys(signedRoot, SignableRootFields)
	payload, err := CanonicalJSONBytes(signable)
	if err != nil {
		return false
	}
	sigB64, _ := getString(signedRoot, "root_signature_b64")
	sigBytes, err := b64Decode(sigB64)
	if err != nil {
		return false
	}
	return VerifySignature(pubKey, payload, sigBytes)
}

// ChainStatus is the outcome of [VerifyRootChain].
type ChainStatus string

// Possible root-chain outcomes. ChainCaveat is a non-fatal warning: the
// predecessor was claimed but not embedded in this bundle, so only a full
// online walk (out of scope for offline verification) can confirm it.
const (
	ChainOK     ChainStatus = "ok"
	ChainFailed ChainStatus = "failed"
	ChainCaveat ChainStatus = "caveat"
)

// ChainResult is the outcome of [VerifyRootChain].
type ChainResult struct {
	Status ChainStatus
	Detail string
}

// VerifyRootChain is Step 5: root-chain continuity. prevSignedRoot is the
// predecessor's signed root map embedded in the bundle (:prev_signed_root),
// or nil if not embedded.
func VerifyRootChain(signedRoot, prevSignedRoot map[string]interface{}, pubKey interface{}) ChainResult {
	prevIDVal, exists := signedRoot["prev_root_id"]
	if !exists || prevIDVal == nil {
		return ChainResult{ChainOK, "genesis root (no predecessor to verify)"}
	}
	if prevSignedRoot == nil {
		prevID, _ := prevIDVal.(string)
		return ChainResult{ChainCaveat, fmt.Sprintf(
			"prev-root-id=%s claimed but predecessor not embedded; full walk is the in-service job", prevID)}
	}
	prevSigOK := VerifyRootSignature(prevSignedRoot, pubKey)
	curPrevHash, _ := getString(signedRoot, "prev_root_hash_b64")
	prevRootHash, _ := getString(prevSignedRoot, "root_hash_b64")
	// Both fields absent must not read as a vacuous match ("" == "") --
	// require a genuinely present, non-empty hash on both sides (i-9e8c).
	hashMatch := curPrevHash != "" && curPrevHash == prevRootHash
	switch {
	case !prevSigOK:
		return ChainResult{ChainFailed, "predecessor root signature verification failed"}
	case !hashMatch:
		return ChainResult{ChainFailed, "prev_root_hash_b64 mismatch: chain link is broken"}
	default:
		return ChainResult{ChainOK, "chain link verified"}
	}
}

// anchorCommandsFor produces human-readable verification commands for each
// anchor type present in anchorRefs.
func anchorCommandsFor(anchorRefs map[string]interface{}) map[string]string {
	out := map[string]string{}
	if immudb, ok := getMap(anchorRefs, "immudb"); ok {
		db, hasDB := getString(immudb, "database")
		if !hasDB {
			db, _ = getString(immudb, "state_db")
		}
		txID, _ := getInt64Loose(immudb, "tx_id")
		s := fmt.Sprintf("immudb-client --db %s tx-get --tx-id %d", db, txID)
		if txHash, ok := getString(immudb, "tx_hash"); ok {
			proofLen := 0
			if p, ok := getSlice(immudb, "inclusion_proof"); ok {
				proofLen = len(p)
			}
			s += fmt.Sprintf("  # tx_hash=%s inclusion_proof_len=%d", txHash, proofLen)
		}
		out["immudb"] = s
	}
	if s3, ok := getMap(anchorRefs, "s3"); ok {
		bucket, _ := getString(s3, "bucket")
		key, _ := getString(s3, "key")
		versionID, _ := getString(s3, "version_id")
		out["s3"] = fmt.Sprintf("mc stat %s/%s --version-id %s", bucket, key, versionID)
	}
	return out
}

// SetStatus is the overall bundle-verification outcome.
type SetStatus string

// Possible overall outcomes.
const (
	SetComplete   SetStatus = "complete"
	SetIncomplete SetStatus = "incomplete"
)

// RecordResult is one record's verification outcome within a [Result].
type RecordResult struct {
	RecordID string
	Status   IntegrityStatus
	Detail   string
	// MerkleOK is nil when the Merkle proof was not checked (e.g. the
	// record's integrity did not verify).
	MerkleOK *bool
	// RootID is the record's own root_id in a set bundle, keying
	// [Result.SignedRootsByID] so callers can render this record's own root
	// hint instead of a bundle-global one. Empty for single-record bundles,
	// which have only one root.
	RootID string
}

// RequireAnchor selects which optional anchor types must be present and
// keyed, turning an absent or unkeyed anchor into a hard failure instead of
// a skip.
type RequireAnchor struct {
	Immudb bool
	S3     bool
}

// Options carries the out-of-band trust roots and policy flags for
// [VerifyBundle].
type Options struct {
	// ImmudbPublicKey is the immudb server's signing key (out-of-band), or
	// nil to skip immudb anchor validation.
	ImmudbPublicKey interface{}
	RequireAnchor   RequireAnchor
}

// Result is the outcome of [VerifyBundle].
type Result struct {
	// ExitCode mirrors the reference CLI's convention: 0 = complete and
	// verified, 1 = tampered/failed, 2 = no sealed records to verify.
	ExitCode    int
	Records     []RecordResult
	RootSigOK   bool
	ChainOK     ChainStatus
	ChainDetail string
	// FloorOK is nil when the retention policy could not be parsed --
	// callers must treat nil as a failure, never as a silent pass.
	FloorOK      *bool
	SetStatus    SetStatus
	AnchorCmds   map[string]string
	ImmudbResult *ImmudbResult
	// S3Result is s3's offline content_sha256 binding outcome (no key
	// required -- see VerifyS3Anchor).
	S3Result *S3Result
	// SignedRoot is populated for single-record bundles.
	SignedRoot map[string]interface{}
	// SignedRootsByID is populated for set bundles: root_id -> that root's
	// signed_root map, so callers can look up a [RecordResult]'s own root via
	// its RootID instead of a single bundle-global root.
	SignedRootsByID map[string]map[string]interface{}
}

func verifySingleRecord(bundle map[string]interface{}, pubKey interface{}, trustedNowMs int64, opts Options) (Result, error) {
	record, _ := getMap(bundle, "record")
	merkleProof, _ := getMap(bundle, "merkle_proof")
	signedRoot, ok := getMap(bundle, "signed_root")
	if !ok {
		return Result{}, errors.New("verify: structurally broken bundle: required field signed_root is missing")
	}
	anchorRefs, _ := getMap(bundle, "anchor_refs")
	prevSignedRoot, _ := getMap(bundle, "prev_signed_root")

	integrityR := VerifyRecordIntegrity(record, pubKey)
	verified := integrityR.Status == StatusVerified

	var merkleOK *bool
	if verified {
		integrity, _ := getMap(record, "integrity")
		leafHashB64, _ := getString(integrity, "leaf_hash_b64")
		if leafHash, err := b64Decode(leafHashB64); err == nil {
			ok := VerifyMerkleInclusion(leafHash, signedRoot, merkleProof)
			merkleOK = &ok
		}
	}

	rootSigOK := VerifyRootSignature(signedRoot, pubKey)
	chainR := VerifyRootChain(signedRoot, prevSignedRoot, pubKey)

	var floorOK *bool
	if tsMs, hasTS := getInt64(signedRoot, "notary_ts_to"); hasTS {
		retentionPolicy, _ := getMap(signedRoot, "retention_policy")
		floorOK = retentionFloorOK(tsMs, retentionPolicy, trustedNowMs)
	} else {
		t := true
		floorOK = &t
	}

	anchorCmds := anchorCommandsFor(anchorRefs)
	rootID, _ := getString(bundle, "root_id")
	immudbR := VerifyImmudbAnchor(anchorRefs, opts.ImmudbPublicKey, opts.RequireAnchor.Immudb, rootID, signedRoot)
	s3R := VerifyS3Anchor(anchorRefs, opts.RequireAnchor.S3, signedRoot)

	tampered := integrityR.Status == StatusTampered ||
		(merkleOK != nil && !*merkleOK) ||
		!rootSigOK ||
		chainR.Status == ChainFailed ||
		immudbR.Status == AnchorFailed ||
		s3R.Status == AnchorFailed

	setStatus := SetIncomplete
	if verified && !tampered {
		setStatus = SetComplete
	}

	return Result{
		Records: []RecordResult{{
			RecordID: "<bundle-record>",
			Status:   integrityR.Status,
			Detail:   integrityR.Detail,
			MerkleOK: merkleOK,
		}},
		RootSigOK:    rootSigOK,
		ChainOK:      chainR.Status,
		ChainDetail:  chainR.Detail,
		FloorOK:      floorOK,
		SetStatus:    setStatus,
		AnchorCmds:   anchorCmds,
		ImmudbResult: &immudbR,
		S3Result:     &s3R,
		SignedRoot:   signedRoot,
	}, nil
}

type rootEntry struct {
	id string
	m  map[string]interface{}
}

// aggregateAnchorResults calls verify once per root in signedRoots (the
// authoritative root list, not anchor_refs_by_root's own keys, so a
// missing/empty anchor_refs_by_root map or a non-map per-root entry can't
// silently skip a root's anchor requirement) and derives anyFail and the
// first AnchorVerified result from that single pass, alongside a per-root
// result map for callers that need one. A non-map anchor_refs_by_root entry
// is treated as absent (nil map). verify receives each root's id (not just
// its anchor-refs map) so a per-root binding check -- e.g. immudb's
// entry-hash-to-root check, or s3's content_sha256-to-root check -- can look
// up that root's own signed_roots[id] fields (signedRoots is available to
// the caller's closure by capture).
func aggregateAnchorResults[T any](signedRoots, anchorRefsByRoot map[string]interface{}, verify func(id string, anchorRefs map[string]interface{}) T, statusOf func(T) AnchorStatus) (anyFail bool, firstOK *T, byRoot map[string]*T) {
	byRoot = make(map[string]*T, len(signedRoots))
	for id := range signedRoots {
		m, _ := anchorRefsByRoot[id].(map[string]interface{})
		r := verify(id, m)
		byRoot[id] = &r
		switch statusOf(r) {
		case AnchorFailed:
			anyFail = true
		case AnchorVerified:
			if firstOK == nil {
				firstOK = &r
			}
		}
	}
	return anyFail, firstOK, byRoot
}

// anchorRootCounts tallies how many roots in byRoot verified vs the total
// root count, so callers can render a partial-coverage summary (e.g.
// "verified for 2 of 3 roots; 1 skipped") instead of a single arbitrary
// first-OK result that silently overstates coverage when some roots were
// only skipped, not verified (see i-5fbz).
func anchorRootCounts[T any](byRoot map[string]*T, statusOf func(T) AnchorStatus) (verified, skipped, total int) {
	total = len(byRoot)
	for _, r := range byRoot {
		switch statusOf(*r) {
		case AnchorVerified:
			verified++
		case AnchorSkipped:
			skipped++
		}
	}
	return verified, skipped, total
}

func verifyMultiRecord(bundle map[string]interface{}, pubKey interface{}, trustedNowMs int64, opts Options) (Result, error) {
	recordsRaw, hasRecords := getSlice(bundle, "records")
	signedRoots, hasSignedRoots := getMap(bundle, "signed_roots")
	if !hasRecords && !hasSignedRoots {
		return Result{}, errors.New("verify: structurally broken bundle: both records and signed_roots are missing")
	}
	anchorRefsByRoot, _ := getMap(bundle, "anchor_refs_by_root")

	recordResults := make([]RecordResult, 0, len(recordsRaw))
	for _, raw := range recordsRaw {
		rm, _ := raw.(map[string]interface{})
		recordID, hasRecordID := getString(rm, "record_id")
		record, _ := getMap(rm, "record")
		merkleProof, hasMP := getMap(rm, "merkle_proof")
		rootID, hasRootID := getString(rm, "root_id")

		ir := VerifyRecordIntegrity(record, pubKey)
		var merkleOK *bool
		if ir.Status == StatusVerified {
			integrity, _ := getMap(record, "integrity")
			leafHashB64, _ := getString(integrity, "leaf_hash_b64")
			leafHash, err := b64Decode(leafHashB64)
			if err != nil {
				f := false
				merkleOK = &f
			} else {
				var sr map[string]interface{}
				if hasRootID {
					sr, _ = getMap(signedRoots, rootID)
				}
				if sr != nil && hasMP {
					ok := VerifyMerkleInclusion(leafHash, sr, merkleProof)
					merkleOK = &ok
				} else {
					f := false
					merkleOK = &f
				}
			}
		}
		if !hasRecordID {
			recordID = "<unknown>"
		}
		recordResults = append(recordResults, RecordResult{RecordID: recordID, Status: ir.Status, Detail: ir.Detail, MerkleOK: merkleOK, RootID: rootID})
	}

	signedRootsByID := make(map[string]map[string]interface{}, len(signedRoots))
	for id, v := range signedRoots {
		if m, ok := v.(map[string]interface{}); ok {
			signedRootsByID[id] = m
		}
	}

	// Root signatures: every? is vacuously true on empty in the reference
	// implementation, but that would make an anchor_refs-less bundle look
	// signature-clean, so require at least one signed root.
	rootSigsOK := len(signedRoots) > 0
	for _, v := range signedRoots {
		srMap, ok := v.(map[string]interface{})
		if !ok || !VerifyRootSignature(srMap, pubKey) {
			rootSigsOK = false
			break
		}
	}

	anchorCmds := map[string]string{}
	for _, v := range anchorRefsByRoot {
		if m, ok := v.(map[string]interface{}); ok {
			for k, val := range anchorCommandsFor(m) {
				anchorCmds[k] = val
			}
		}
	}

	roots := make([]rootEntry, 0, len(signedRoots))
	for id, v := range signedRoots {
		if m, ok := v.(map[string]interface{}); ok {
			roots = append(roots, rootEntry{id: id, m: m})
		}
	}
	allHaveCoveredRange := true
	for _, r := range roots {
		if _, ok := getMap(r.m, "covered_range"); !ok {
			allHaveCoveredRange = false
			break
		}
	}
	// roots is built by iterating signedRoots, a map, so its base order is
	// randomized per process. Sort by id first to give every downstream
	// consumer (chain walk, floorOK, outerCaveat, span checks) a
	// deterministic order even when covered_range is absent below.
	sortedRoots := roots
	sort.SliceStable(sortedRoots, func(i, j int) bool {
		return sortedRoots[i].id < sortedRoots[j].id
	})
	if allHaveCoveredRange {
		sort.SliceStable(sortedRoots, func(i, j int) bool {
			cri, _ := getMap(sortedRoots[i].m, "covered_range")
			crj, _ := getMap(sortedRoots[j].m, "covered_range")
			fi, _ := getInt64(cri, "from_seq")
			fj, _ := getInt64(crj, "from_seq")
			return fi < fj
		})
	}

	// Retention floor is evaluated only against the earliest root
	// (sortedRoots[0]), not per-root. This is an intentional simplification
	// mirroring a known, documented limitation in the reference Clojure
	// implementation, not an oversight.
	var floorOK *bool
	if len(sortedRoots) > 0 {
		first := sortedRoots[0].m
		if tsMs, hasTS := getInt64(first, "notary_ts_to"); hasTS {
			retentionPolicy, _ := getMap(first, "retention_policy")
			floorOK = retentionFloorOK(tsMs, retentionPolicy, trustedNowMs)
		} else {
			t := true
			floorOK = &t
		}
	} else {
		t := true
		floorOK = &t
	}

	outerCaveat := false
	if len(sortedRoots) > 0 {
		if prevIDVal, exists := sortedRoots[0].m["prev_root_id"]; exists && prevIDVal != nil {
			if s, ok := prevIDVal.(string); ok && s != "" {
				outerCaveat = true
			}
		}
	}

	innerOK := true
	var gapAt *int64
	if len(sortedRoots) >= 2 {
		for i := 0; i < len(sortedRoots)-1 && innerOK; i++ {
			prevR := sortedRoots[i].m
			nextR := sortedRoots[i+1].m
			prevHash, _ := getString(prevR, "root_hash_b64")
			nextPrevHash, _ := getString(nextR, "prev_root_hash_b64")
			// prevHash == "" must fail closed, not vacuously match an
			// equally-absent nextPrevHash (i-9e8c).
			if prevHash == "" || prevHash != nextPrevHash {
				innerOK = false
				if cr, ok := getMap(nextR, "covered_range"); ok {
					if fs, ok := getInt64(cr, "from_seq"); ok {
						gapAt = &fs
					}
				}
			}
		}
	}
	var chainStatus ChainStatus
	switch {
	case !innerOK:
		chainStatus = ChainFailed
	case outerCaveat:
		chainStatus = ChainCaveat
	default:
		chainStatus = ChainOK
	}
	var chainDetail string
	switch chainStatus {
	case ChainCaveat:
		chainDetail = "first root claims predecessor outside bundle; full chain walk is the in-service job"
	case ChainOK:
		chainDetail = "chain links verified"
	default:
		if gapAt != nil {
			chainDetail = fmt.Sprintf("gap at seq %d", *gapAt)
		} else {
			chainDetail = "gap at seq <unknown>"
		}
	}

	immudbAnyFail, _, immudbByRoot := aggregateAnchorResults(signedRoots, anchorRefsByRoot,
		func(id string, m map[string]interface{}) ImmudbResult {
			sr, _ := getMap(signedRoots, id)
			return VerifyImmudbAnchor(m, opts.ImmudbPublicKey, opts.RequireAnchor.Immudb, id, sr)
		},
		func(r ImmudbResult) AnchorStatus { return r.Status },
	)
	var immudbResult *ImmudbResult
	switch {
	case immudbAnyFail:
		immudbResult = &ImmudbResult{Status: AnchorFailed, Detail: "one or more root immudb anchors failed validation"}
	default:
		verified, _, total := anchorRootCounts(immudbByRoot, func(r ImmudbResult) AnchorStatus { return r.Status })
		switch verified {
		case 0:
			// No root verified anywhere (all skipped) -- nothing to
			// summarize, matching the prior single-root-bundle behavior.
			immudbResult = nil
		case total:
			immudbResult = &ImmudbResult{Status: AnchorVerified, Detail: fmt.Sprintf("immudb anchor verified for all %d root(s)", total)}
		default:
			// Some roots verified, some were skipped (no anchor / no key)
			// -- must not read as full coverage (i-5fbz).
			immudbResult = &ImmudbResult{Status: AnchorVerified, Detail: fmt.Sprintf("immudb anchor verified for %d of %d roots; %d skipped", verified, total, total-verified)}
		}
	}

	s3AnyFail, _, s3ByRoot := aggregateAnchorResults(signedRoots, anchorRefsByRoot,
		func(id string, m map[string]interface{}) S3Result {
			sr, _ := getMap(signedRoots, id)
			return VerifyS3Anchor(m, opts.RequireAnchor.S3, sr)
		},
		func(r S3Result) AnchorStatus { return r.Status },
	)
	var s3Result *S3Result
	switch {
	case s3AnyFail:
		s3Result = &S3Result{Status: AnchorFailed, Detail: "one or more root s3 anchors failed validation"}
	default:
		verified, _, total := anchorRootCounts(s3ByRoot, func(r S3Result) AnchorStatus { return r.Status })
		switch verified {
		case 0:
			// No root verified anywhere (all skipped) -- nothing to
			// summarize, matching the immudb aggregation's convention.
			s3Result = nil
		case total:
			s3Result = &S3Result{Status: AnchorVerified, Detail: fmt.Sprintf("s3 anchor verified for all %d root(s)", total)}
		default:
			// Some roots verified, some were skipped -- must not read as
			// full coverage (i-5fbz).
			s3Result = &S3Result{Status: AnchorVerified, Detail: fmt.Sprintf("s3 anchor verified for %d of %d roots; %d skipped", verified, total, total-verified)}
		}
	}

	anyTampered := false
	anyMerkleFail := false
	allVerified := true
	for _, r := range recordResults {
		if r.Status == StatusTampered {
			anyTampered = true
		}
		if r.MerkleOK != nil && !*r.MerkleOK {
			anyMerkleFail = true
		}
		if r.Status != StatusVerified {
			allVerified = false
		}
	}

	setStatus := SetIncomplete
	switch {
	case anyTampered || !rootSigsOK || anyMerkleFail || immudbAnyFail || s3AnyFail:
		setStatus = SetIncomplete
	case chainStatus == ChainFailed:
		setStatus = SetIncomplete
	case allVerified:
		setStatus = SetComplete
	}

	return Result{
		Records:         recordResults,
		RootSigOK:       rootSigsOK,
		ChainOK:         chainStatus,
		ChainDetail:     chainDetail,
		FloorOK:         floorOK,
		SetStatus:       setStatus,
		AnchorCmds:      anchorCmds,
		ImmudbResult:    immudbResult,
		S3Result:        s3Result,
		SignedRootsByID: signedRootsByID,
	}, nil
}

// VerifyBundle verifies a decoded bundle (see DecodeBundle) against pubKey,
// the notary's public key parsed with [ParsePublicKey]. trustedNowMs is the
// verifier's trusted wall-clock (epoch-ms) used for Step 6's retention-floor
// evaluation. opts carries the optional out-of-band anchor public keys and
// the --require-anchor policy.
//
// A bundle with a top-level "record" key (even if null) is treated as a
// single-record bundle; otherwise it is treated as a set bundle. A bundle
// carrying both shapes at once (a "record" key alongside "records" or
// "signed_roots") is structurally ambiguous and rejected outright: routing
// it to verifySingleRecord would validate only the single-record fields and
// silently ignore an attacker-supplied "records"/"signed_roots" payload
// riding alongside a genuine, legitimately-signed single record -- letting a
// tampered set bundle be smuggled through and reported VERIFIED.
func VerifyBundle(bundle map[string]interface{}, pubKey interface{}, trustedNowMs int64, opts Options) (Result, error) {
	meta, hasMeta := getMap(bundle, "meta")
	if !hasMeta {
		return Result{}, errors.New("verify: missing bundle meta; not a Manetu verification bundle")
	}
	metaType, _ := getString(meta, "type")
	if metaType != bundleMetaType {
		return Result{}, fmt.Errorf("verify: unrecognized bundle meta.type %q; not a Manetu verification bundle", metaType)
	}
	schemaVersion, _ := getString(meta, "schema_version")
	major, _, ok := strings.Cut(schemaVersion, ".")
	if !ok || major != supportedSchemaMajor {
		return Result{}, fmt.Errorf("verify: unsupported schema_version %q; this verifier supports %s.x", schemaVersion, supportedSchemaMajor)
	}

	var result Result
	_, hasRecord := bundle["record"]
	_, hasRecords := bundle["records"]
	_, hasSignedRoots := bundle["signed_roots"]
	if hasRecord && (hasRecords || hasSignedRoots) {
		return Result{}, errors.New("verify: structurally ambiguous bundle: \"record\" present alongside \"records\"/\"signed_roots\"")
	}
	// bundle_kind is advisory only (unsigned): the structural key-presence
	// check above/below remains the sole routing authority. This is purely a
	// self-consistency cross-check -- a mismatch is a signal the bundle was
	// hand-tampered or mis-assembled.
	wantKind := "set"
	if hasRecord {
		wantKind = "record"
	}
	if bundleKind, _ := getString(meta, "bundle_kind"); bundleKind != wantKind {
		return Result{}, fmt.Errorf("verify: meta.bundle_kind %q inconsistent with bundle structure (expected %q)", bundleKind, wantKind)
	}
	if hasRecord {
		var err error
		result, err = verifySingleRecord(bundle, pubKey, trustedNowMs, opts)
		if err != nil {
			return Result{}, err
		}
	} else {
		var err error
		result, err = verifyMultiRecord(bundle, pubKey, trustedNowMs, opts)
		if err != nil {
			return Result{}, err
		}
	}

	anyTampered := false
	allUnverified := true
	for _, r := range result.Records {
		if r.Status == StatusTampered {
			anyTampered = true
		}
		if r.Status != StatusUnverifiedNotSealed {
			allUnverified = false
		}
	}
	immudbFail := result.ImmudbResult != nil && result.ImmudbResult.Status == AnchorFailed
	s3Fail := result.S3Result != nil && result.S3Result.Status == AnchorFailed

	switch {
	case anyTampered || !result.RootSigOK || immudbFail || s3Fail:
		result.ExitCode = 1
	case result.ChainOK == ChainFailed:
		result.ExitCode = 1
	case result.FloorOK == nil:
		result.ExitCode = 1
	case allUnverified:
		result.ExitCode = 2
	case result.SetStatus == SetComplete:
		result.ExitCode = 0
	default:
		result.ExitCode = 1
	}
	return result, nil
}
