//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordFixture is one record's plaintext + its integrity envelope, built
// from a keypair, ready to be embedded in a bundle and hashed into a batch
// Merkle tree alongside other records.
type recordFixture struct {
	recordPB []byte
	leafHash []byte
	record   map[string]interface{} // normalized :record sub-map
}

func buildRecordFixture(t *testing.T, kp testKeyPair, payload string) recordFixture {
	t.Helper()
	recordPB := []byte(payload)
	leafHash := LeafHash(recordPB)
	sig := kp.sign(leafHash)
	record := normalizeJSON(t, map[string]interface{}{
		"record_pb_b64": base64.RawURLEncoding.EncodeToString(recordPB),
		"integrity": map[string]interface{}{
			"leaf_hash_b64": base64.RawURLEncoding.EncodeToString(leafHash),
			"signature_b64": base64.RawURLEncoding.EncodeToString(sig),
			"key_id":        "test-key",
			"sig_alg":       "Ed25519",
		},
	})
	return recordFixture{recordPB: recordPB, leafHash: leafHash, record: record}
}

// merkleProofFixture builds a bundle merkle_proof map for the leaf at
// leafIndex in tree. offset is the record's Kafka offset (merkle_proof.
// offset) -- part of the positioned leaf preimage tree's leaves are built
// from (see positionedLeaf/buildPositionedTree); it must be present for
// VerifyMerkleInclusion to recompute that same preimage.
func merkleProofFixture(t *testing.T, tree [][][]byte, leafIndex int, offset int64) map[string]interface{} {
	t.Helper()
	proof, err := InclusionProof(tree, leafIndex)
	require.NoError(t, err)
	auditPath := make([]interface{}, len(proof))
	for i, step := range proof {
		side := "right"
		if step.Side == SideLeft {
			side = "left"
		}
		auditPath[i] = map[string]interface{}{
			"hash_b64": base64.RawURLEncoding.EncodeToString(step.Hash),
			"side":     side,
		}
	}
	return normalizeJSON(t, map[string]interface{}{
		"leaf_index": leafIndex,
		"offset":     offset,
		"audit_path": auditPath,
	})
}

// positionedLeaf pairs a record's own per-record leaf hash with its Kafka
// offset, for buildPositionedTree.
type positionedLeaf struct {
	leafHash []byte
	offset   int64
}

// buildPositionedTree builds an RFC 6962 tree over leaves' positioned leaf
// preimages (Design D1: the tree's actual leaf preimage binds tree
// position, not just content -- see PositionedLeafHash), given the batch's
// partition and sealing notary_ts_to. partition and notaryTs must match the
// signed_root these leaves are ultimately sealed under, and each leaf's
// offset must match its merkle_proof.offset (see merkleProofFixture),
// since VerifyMerkleInclusion recomputes this exact positioning from
// signedRoot.partition/notary_ts_to and merkle_proof.offset/leaf_index.
func buildPositionedTree(t *testing.T, leaves []positionedLeaf, partition, notaryTs int64) [][][]byte {
	t.Helper()
	positioned := make([][]byte, len(leaves))
	for i, l := range leaves {
		contentB64 := base64.RawURLEncoding.EncodeToString(l.leafHash)
		ph, err := PositionedLeafHash(partition, l.offset, int64(i), notaryTs, contentB64)
		require.NoError(t, err)
		positioned[i] = ph
	}
	return BuildTree(positioned)
}

func rootHashFixture(t *testing.T, tree [][][]byte) string {
	t.Helper()
	root, err := Root(tree)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(root)
}

// buildSignedRootBase builds a normalized, signed signed_root map covering
// exactly one batch. notaryTsTo is reused for both notary_ts_from and
// notary_ts_to -- fine for test fixtures representing a single
// point-in-time seal; partition_count is fixed at 1, an arbitrary valid
// placeholder used consistently across fixtures.
func buildSignedRootBase(t *testing.T, kp testKeyPair, rootHashB64 string, treeSize, fromSeq, toSeq int, prevRootID, prevRootHashB64 interface{}, notaryTsTo int64) map[string]interface{} {
	t.Helper()
	root := normalizeJSON(t, map[string]interface{}{
		"root_hash_b64":      rootHashB64,
		"tree_size":          treeSize,
		"partition":          0,
		"partition_count":    1,
		"covered_range":      map[string]interface{}{"from_seq": fromSeq, "to_seq": toSeq},
		"prev_root_hash_b64": prevRootHashB64,
		"prev_root_id":       prevRootID,
		"notary_ts_from":     notaryTsTo,
		"notary_ts_to":       notaryTsTo,
		"retention_policy":   map[string]interface{}{"mode": "retain-all"},
	})
	signRoot(t, kp, root)
	return root
}

func singleRecordBundle(t *testing.T, kp testKeyPair) (map[string]interface{}, recordFixture) {
	t.Helper()
	rec := buildRecordFixture(t, kp, "access-record-1")
	tree := buildPositionedTree(t, []positionedLeaf{{leafHash: rec.leafHash, offset: 0}}, 0, 1_700_000_000_000)
	signedRoot := buildSignedRootBase(t, kp, rootHashFixture(t, tree), 1, 0, 0, nil, nil, 1_700_000_000_000)
	bundle := normalizeJSON(t, map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           bundleMetaType,
			"schema_version": "2.0",
			"bundle_kind":    "record",
		},
		"record":       rec.record,
		"merkle_proof": merkleProofFixture(t, tree, 0, 0),
		"signed_root":  signedRoot,
		"anchor_refs":  map[string]interface{}{},
	})
	return bundle, rec
}

func TestVerifyBundleSingleRecordVerified(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, SetComplete, result.SetStatus)
	require.Len(t, result.Records, 1)
	assert.Equal(t, StatusVerified, result.Records[0].Status)
	require.NotNil(t, result.Records[0].MerkleOK)
	assert.True(t, *result.Records[0].MerkleOK)
	assert.True(t, result.RootSigOK)
	assert.Equal(t, ChainOK, result.ChainOK)
}

// TestVerifyBundleSingleRecordVerifiedECDSA is the regression for i-6v11:
// every other bundle-level test in this file uses Ed25519 exclusively: the
// ECDSA-P256-SHA256 path (VerifySignature's sha256-prehash-then-VerifyASN1
// branch, keys.go:56) was previously only exercised at the primitive level
// in keys_test.go, never through the full VerifyBundle path -- covering
// both the per-record leaf signature (VerifyRecordIntegrity) and the root
// signature (VerifyRootSignature, over the canonical-JSON payload) in one
// pass, since testKeyPair abstracts over both algorithms identically.
func TestVerifyBundleSingleRecordVerifiedECDSA(t *testing.T) {
	t.Parallel()

	kp := genECDSAKeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, SetComplete, result.SetStatus)
	require.Len(t, result.Records, 1)
	assert.Equal(t, StatusVerified, result.Records[0].Status)
	require.NotNil(t, result.Records[0].MerkleOK)
	assert.True(t, *result.Records[0].MerkleOK)
	assert.True(t, result.RootSigOK)
	assert.Equal(t, ChainOK, result.ChainOK)
}

// TestVerifyBundleSingleRecordWrongECDSAKeyFails confirms the ECDSA path
// fails closed against the wrong key, mirroring the Ed25519 coverage
// elsewhere in this file -- a bundle signed by one ECDSA-P256 key must not
// verify against a different one.
func TestVerifyBundleSingleRecordWrongECDSAKeyFails(t *testing.T) {
	t.Parallel()

	kp := genECDSAKeyPair(t)
	other := genECDSAKeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	result, err := VerifyBundle(bundle, other.pub, 1_700_000_000_000, Options{})
	require.NoError(t, err)
	assert.NotEqual(t, 0, result.ExitCode)
	assert.False(t, result.RootSigOK)
}

func TestVerifyBundleSingleRecordTamperedLeaf(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	// Flip a byte in the record bytes without re-signing -- the leaf hash
	// recomputation in Step 1 must catch this.
	record := bundle["record"].(map[string]interface{})
	record["record_pb_b64"] = base64.RawURLEncoding.EncodeToString([]byte("tampered-record!"))

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ExitCode)
	assert.Equal(t, SetIncomplete, result.SetStatus)
	assert.Equal(t, StatusTampered, result.Records[0].Status)
}

func TestVerifyBundleSingleRecordTamperedRootSignature(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	signedRoot := bundle["signed_root"].(map[string]interface{})
	signedRoot["tree_size"] = int64(999) // signed field changed post-signature

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ExitCode)
	assert.False(t, result.RootSigOK)
}

func TestVerifyBundleSingleRecordWrongKeyFails(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	other := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)

	result, err := VerifyBundle(bundle, other.pub, 1_700_000_000_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ExitCode)
	assert.Equal(t, StatusTampered, result.Records[0].Status)
	assert.False(t, result.RootSigOK)
}

func TestVerifyBundleUnverifiedNotSealed(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	bundle["record"] = nil // present key, null value: contains? bundle :record is still true

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
	assert.Equal(t, StatusUnverifiedNotSealed, result.Records[0].Status)
}

// TestVerifyBundleAmbiguousShapeRejected is the regression for the dispatch
// finding in the code review of ac82395: a bundle carrying a genuine,
// legitimately-signed "record" alongside a tampered "records"/"signed_roots"
// payload must not be routed to verifySingleRecord, which would validate
// only the single-record fields and silently ignore the smuggled set data.
func TestVerifyBundleAmbiguousShapeRejected(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	bundle["records"] = []interface{}{
		map[string]interface{}{"record_id": "tampered-1"},
	}

	_, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.Error(t, err)
}

// TestVerifyBundleAmbiguousShapeWithSignedRootsRejected covers the
// signed_roots variant of the same ambiguity.
func TestVerifyBundleAmbiguousShapeWithSignedRootsRejected(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	bundle["signed_roots"] = map[string]interface{}{
		"tampered-root": map[string]interface{}{},
	}

	_, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.Error(t, err)
}

// TestVerifyBundleAmbiguousShapeNullRecordRejected covers the weaker variant
// noted in review: record: null alongside records/signed_roots must still
// be rejected as ambiguous, not silently downgraded to
// UNVERIFIED-NOT-SEALED (which would also mask tampering in the set data).
func TestVerifyBundleAmbiguousShapeNullRecordRejected(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	bundle["record"] = nil
	bundle["records"] = []interface{}{
		map[string]interface{}{"record_id": "tampered-1"},
	}

	_, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.Error(t, err)
}

// --- meta envelope precondition gate (s-5k1l/i-4brg) -----------------------
//
// These mirror the acceptance matrix designed alongside the reference
// Clojure verifier's check-meta-precondition! (mpe-iam-lite issue i-3y9t).
// The meta envelope is unsigned -- it can only ever gate whether a bundle is
// accepted for processing at all, never substitute for a cryptographic
// check -- so every rejection case here must produce a non-nil error before
// any record/root verification runs, and no case may produce a passing
// Result from a malformed or absent meta (no fail-open).

func TestVerifyBundleMetaAbsentRejected(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	delete(bundle, "meta")

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.Error(t, err)
	assert.Equal(t, Result{}, result, "no fail-open: a rejected bundle must not carry a usable Result")
}

func TestVerifyBundleMetaWrongTypeRejected(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	bundle["meta"].(map[string]interface{})["type"] = "some-other-artifact"

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.Error(t, err)
	assert.Equal(t, Result{}, result)
}

func TestVerifyBundleMetaUnsupportedMajorRejected(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	bundle["meta"].(map[string]interface{})["schema_version"] = "3.0"

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.Error(t, err)
	assert.Equal(t, Result{}, result)
}

// TestVerifyBundleMetaGreaterMinorAccepted confirms additive
// forward-compatibility: a bundle reporting a MINOR ahead of what this
// verifier was written against is accepted, not refused, since a MINOR bump
// is defined to only ever add optional fields.
func TestVerifyBundleMetaGreaterMinorAccepted(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	bundle["meta"].(map[string]interface{})["schema_version"] = "2.9"

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
}

func TestVerifyBundleMetaBundleKindMismatchRejected(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	bundle["meta"].(map[string]interface{})["bundle_kind"] = "set"

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.Error(t, err)
	assert.Equal(t, Result{}, result)
}

func TestVerifyBundleMissingSignedRootErrors(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	delete(bundle, "signed_root")

	_, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	assert.Error(t, err)
}

func TestVerifyBundleRootChainAcrossTwoBundles(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	rec1 := buildRecordFixture(t, kp, "access-record-1")
	tree1 := buildPositionedTree(t, []positionedLeaf{{leafHash: rec1.leafHash, offset: 0}}, 0, 1_700_000_000_000)
	root1 := buildSignedRootBase(t, kp, rootHashFixture(t, tree1), 1, 0, 0, nil, nil, 1_700_000_000_000)

	rec2 := buildRecordFixture(t, kp, "access-record-2")
	tree2 := buildPositionedTree(t, []positionedLeaf{{leafHash: rec2.leafHash, offset: 1}}, 0, 1_700_000_100_000)
	root1HashB64, _ := getString(root1, "root_hash_b64")
	root2 := buildSignedRootBase(t, kp, rootHashFixture(t, tree2), 1, 1, 1, "root-1", root1HashB64, 1_700_000_100_000)

	bundle := normalizeJSON(t, map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           bundleMetaType,
			"schema_version": "2.0",
			"bundle_kind":    "record",
		},
		"record":           rec2.record,
		"merkle_proof":     merkleProofFixture(t, tree2, 0, 1),
		"signed_root":      root2,
		"anchor_refs":      map[string]interface{}{},
		"prev_signed_root": root1,
	})

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, ChainOK, result.ChainOK)
}

func TestVerifyBundleRootChainBrokenLink(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	rec1 := buildRecordFixture(t, kp, "access-record-1")
	tree1 := buildPositionedTree(t, []positionedLeaf{{leafHash: rec1.leafHash, offset: 0}}, 0, 1_700_000_000_000)
	root1 := buildSignedRootBase(t, kp, rootHashFixture(t, tree1), 1, 0, 0, nil, nil, 1_700_000_000_000)

	rec2 := buildRecordFixture(t, kp, "access-record-2")
	tree2 := buildPositionedTree(t, []positionedLeaf{{leafHash: rec2.leafHash, offset: 1}}, 0, 1_700_000_100_000)
	// Deliberately wrong prev_root_hash_b64 -- doesn't match root1's actual hash.
	root2 := buildSignedRootBase(t, kp, rootHashFixture(t, tree2), 1, 1, 1, "root-1", "not-the-real-prev-hash", 1_700_000_100_000)

	bundle := normalizeJSON(t, map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           bundleMetaType,
			"schema_version": "2.0",
			"bundle_kind":    "record",
		},
		"record":           rec2.record,
		"merkle_proof":     merkleProofFixture(t, tree2, 0, 1),
		"signed_root":      root2,
		"anchor_refs":      map[string]interface{}{},
		"prev_signed_root": root1,
	})

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ExitCode)
	assert.Equal(t, ChainFailed, result.ChainOK)
}

// TestVerifyBundleRootChainBothHashesAbsentFailsClosed is the regression for
// i-9e8c: if a non-genesis root's prev_root_hash_b64 is absent AND its
// embedded predecessor's own root_hash_b64 is also absent, the chain link
// must not vacuously "match" ("" == ""). root1 (the predecessor) has its
// root_hash_b64 stripped and is re-signed over the remaining signable
// fields; root2's prev_root_hash_b64 is left null (absent), matching a
// genesis-shaped predecessor reference.
func TestVerifyBundleRootChainBothHashesAbsentFailsClosed(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	rec1 := buildRecordFixture(t, kp, "access-record-1")
	tree1 := buildPositionedTree(t, []positionedLeaf{{leafHash: rec1.leafHash, offset: 0}}, 0, 1_700_000_000_000)
	root1 := buildSignedRootBase(t, kp, rootHashFixture(t, tree1), 1, 0, 0, nil, nil, 1_700_000_000_000)
	delete(root1, "root_hash_b64")
	signRoot(t, kp, root1)

	rec2 := buildRecordFixture(t, kp, "access-record-2")
	tree2 := buildPositionedTree(t, []positionedLeaf{{leafHash: rec2.leafHash, offset: 1}}, 0, 1_700_000_100_000)
	root2 := buildSignedRootBase(t, kp, rootHashFixture(t, tree2), 1, 1, 1, "root-1", nil, 1_700_000_100_000)

	bundle := normalizeJSON(t, map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           bundleMetaType,
			"schema_version": "2.0",
			"bundle_kind":    "record",
		},
		"record":           rec2.record,
		"merkle_proof":     merkleProofFixture(t, tree2, 0, 1),
		"signed_root":      root2,
		"anchor_refs":      map[string]interface{}{},
		"prev_signed_root": root1,
	})

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ExitCode)
	assert.Equal(t, ChainFailed, result.ChainOK, "both prev_root_hash_b64 and predecessor's root_hash_b64 absent must not vacuously match")
}

func TestVerifyBundleRetentionAuthorizedAbsentIsNotTamper(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	rec := buildRecordFixture(t, kp, "old-record")
	old := int64(1_600_000_000_000)
	tree := buildPositionedTree(t, []positionedLeaf{{leafHash: rec.leafHash, offset: 0}}, 0, old)
	root := normalizeJSON(t, map[string]interface{}{
		"root_hash_b64":      rootHashFixture(t, tree),
		"tree_size":          1,
		"partition":          0,
		"partition_count":    1,
		"covered_range":      map[string]interface{}{"from_seq": 0, "to_seq": 0},
		"prev_root_hash_b64": nil,
		"prev_root_id":       nil,
		"notary_ts_from":     old,
		"notary_ts_to":       old,
		"retention_policy":   map[string]interface{}{"mode": "relative", "P": "P1D"},
	})
	signRoot(t, kp, root)
	bundle := normalizeJSON(t, map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           bundleMetaType,
			"schema_version": "2.0",
			"bundle_kind":    "record",
		},
		"record":       rec.record,
		"merkle_proof": merkleProofFixture(t, tree, 0, 0),
		"signed_root":  root,
		"anchor_refs":  map[string]interface{}{},
	})

	// trustedNow is ~50 days after the record's timestamp with only a 1-day
	// retention window: the record is authorized-absent, but that's a
	// policy fact, not evidence of tampering, so the bundle we DO have
	// still verifies cleanly.
	now := old + 50*24*60*60*1000
	result, err := VerifyBundle(bundle, kp.pub, now, Options{})
	require.NoError(t, err)
	require.NotNil(t, result.FloorOK)
	assert.False(t, *result.FloorOK)
	assert.Equal(t, 0, result.ExitCode, "authorized-absent must not flip exit code to failure")
}

// --- multi-record (set) bundles ---

// buildSetBundle assembles a two-batch, four-record set bundle: batch 0
// covers seq 0-1 (2 records), batch 1 covers seq 2-3 (2 records), chained
// via prev_root_hash_b64/prev_root_id, with a completeness block whose
// [from_seq, to_seq] spans both batches.
func buildSetBundle(t *testing.T, kp testKeyPair) map[string]interface{} {
	t.Helper()
	recs := make([]recordFixture, 4)
	for i := range recs {
		recs[i] = buildRecordFixture(t, kp, "record-"+string(rune('a'+i)))
	}
	tree0 := buildPositionedTree(t, []positionedLeaf{{leafHash: recs[0].leafHash, offset: 0}, {leafHash: recs[1].leafHash, offset: 1}}, 0, 1_700_000_000_000)
	tree1 := buildPositionedTree(t, []positionedLeaf{{leafHash: recs[2].leafHash, offset: 2}, {leafHash: recs[3].leafHash, offset: 3}}, 0, 1_700_000_100_000)

	root0 := buildSignedRootBase(t, kp, rootHashFixture(t, tree0), 2, 0, 1, nil, nil, 1_700_000_000_000)
	root0HashB64, _ := getString(root0, "root_hash_b64")
	root1 := buildSignedRootBase(t, kp, rootHashFixture(t, tree1), 2, 2, 3, "root-0", root0HashB64, 1_700_000_100_000)

	records := []interface{}{
		map[string]interface{}{"record_id": "r0", "root_id": "root-0", "merkle_proof": merkleProofFixture(t, tree0, 0, 0), "record": recs[0].record},
		map[string]interface{}{"record_id": "r1", "root_id": "root-0", "merkle_proof": merkleProofFixture(t, tree0, 1, 1), "record": recs[1].record},
		map[string]interface{}{"record_id": "r2", "root_id": "root-1", "merkle_proof": merkleProofFixture(t, tree1, 0, 2), "record": recs[2].record},
		map[string]interface{}{"record_id": "r3", "root_id": "root-1", "merkle_proof": merkleProofFixture(t, tree1, 1, 3), "record": recs[3].record},
	}

	return normalizeJSON(t, map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           bundleMetaType,
			"schema_version": "2.0",
			"bundle_kind":    "set",
		},
		"records":      records,
		"signed_roots": map[string]interface{}{"root-0": root0, "root-1": root1},
		"anchor_refs_by_root": map[string]interface{}{
			"root-0": map[string]interface{}{},
			"root-1": map[string]interface{}{},
		},
	})
}

func TestVerifyBundleSetComplete(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle := buildSetBundle(t, kp)
	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, SetComplete, result.SetStatus)
	assert.Len(t, result.Records, 4)
	for _, r := range result.Records {
		assert.Equal(t, StatusVerified, r.Status)
		require.NotNil(t, r.MerkleOK)
		assert.True(t, *r.MerkleOK)
	}
}

func TestVerifyBundleSetMissingRecordsAndSignedRootsErrors(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle := buildSetBundle(t, kp)
	delete(bundle, "records")
	delete(bundle, "signed_roots")

	_, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{})
	assert.Error(t, err)
}

// TestVerifyBundleSetBrokenChainLinkFailsClosed: a genuinely broken hash-chain
// link (root-1's prev_root_hash_b64 corrupted) in an otherwise fully-verified
// set bundle must fail closed. s-3vlq / C2 retired the offline completeness
// claim (span/density/coverage checks) this test previously paired the break
// against -- the hash-chain check itself is unaffected and is exercised
// directly here.
func TestVerifyBundleSetBrokenChainLinkFailsClosed(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle := buildSetBundle(t, kp)

	signedRoots := bundle["signed_roots"].(map[string]interface{})
	root1 := signedRoots["root-1"].(map[string]interface{})
	root1["prev_root_hash_b64"] = "corrupted-hash-value"

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ExitCode)
	assert.Equal(t, SetIncomplete, result.SetStatus)
	assert.Equal(t, ChainFailed, result.ChainOK)
}

func TestVerifyBundleSetMissingCoveredRangeIsDeterministic(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	recs := make([]recordFixture, 6)
	for i := range recs {
		recs[i] = buildRecordFixture(t, kp, "record-"+string(rune('a'+i)))
	}
	tree0 := buildPositionedTree(t, []positionedLeaf{{leafHash: recs[0].leafHash, offset: 0}, {leafHash: recs[1].leafHash, offset: 1}}, 0, 1_700_000_000_000)
	tree1 := buildPositionedTree(t, []positionedLeaf{{leafHash: recs[2].leafHash, offset: 2}, {leafHash: recs[3].leafHash, offset: 3}}, 0, 1_700_000_100_000)
	tree2 := buildPositionedTree(t, []positionedLeaf{{leafHash: recs[4].leafHash, offset: 4}, {leafHash: recs[5].leafHash, offset: 5}}, 0, 1_700_000_200_000)

	root0 := buildSignedRootBase(t, kp, rootHashFixture(t, tree0), 2, 0, 1, nil, nil, 1_700_000_000_000)
	root0HashB64, _ := getString(root0, "root_hash_b64")
	root1 := buildSignedRootBase(t, kp, rootHashFixture(t, tree1), 2, 2, 3, "root-0", root0HashB64, 1_700_000_100_000)
	root1HashB64, _ := getString(root1, "root_hash_b64")
	root2 := buildSignedRootBase(t, kp, rootHashFixture(t, tree2), 2, 4, 5, "root-1", root1HashB64, 1_700_000_200_000)

	// root-1 stands in for a heartbeat/idle-partition root that by design
	// never carries a covered_range. Stripping it flips allHaveCoveredRange
	// to false, which is exactly the condition under which sortedRoots used
	// to be left in map-iteration (i.e. random) order. covered_range is part
	// of SignableRootFields, so root-1 must be re-signed after stripping it.
	delete(root1, "covered_range")
	signRoot(t, kp, root1)

	records := []interface{}{
		map[string]interface{}{"record_id": "r0", "root_id": "root-0", "merkle_proof": merkleProofFixture(t, tree0, 0, 0), "record": recs[0].record},
		map[string]interface{}{"record_id": "r1", "root_id": "root-0", "merkle_proof": merkleProofFixture(t, tree0, 1, 1), "record": recs[1].record},
		map[string]interface{}{"record_id": "r2", "root_id": "root-1", "merkle_proof": merkleProofFixture(t, tree1, 0, 2), "record": recs[2].record},
		map[string]interface{}{"record_id": "r3", "root_id": "root-1", "merkle_proof": merkleProofFixture(t, tree1, 1, 3), "record": recs[3].record},
		map[string]interface{}{"record_id": "r4", "root_id": "root-2", "merkle_proof": merkleProofFixture(t, tree2, 0, 4), "record": recs[4].record},
		map[string]interface{}{"record_id": "r5", "root_id": "root-2", "merkle_proof": merkleProofFixture(t, tree2, 1, 5), "record": recs[5].record},
	}

	bundle := normalizeJSON(t, map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           bundleMetaType,
			"schema_version": "2.0",
			"bundle_kind":    "set",
		},
		"records":      records,
		"signed_roots": map[string]interface{}{"root-0": root0, "root-1": root1, "root-2": root2},
		"anchor_refs_by_root": map[string]interface{}{
			"root-0": map[string]interface{}{},
			"root-1": map[string]interface{}{},
			"root-2": map[string]interface{}{},
		},
	})

	first, err := VerifyBundle(bundle, kp.pub, 1_700_000_300_000, Options{})
	require.NoError(t, err)
	// The hash chain root-0 -> root-1 -> root-2 is genuinely intact, so a
	// deterministic verifier must always report ChainOK here -- never
	// ChainFailed from having walked the roots out of order.
	require.Equal(t, ChainOK, first.ChainOK)

	for i := 0; i < 50; i++ {
		result, err := VerifyBundle(bundle, kp.pub, 1_700_000_300_000, Options{})
		require.NoError(t, err)
		assert.Equal(t, first.ExitCode, result.ExitCode, "run %d: ExitCode must be identical across repeated calls on the same bundle bytes", i)
		assert.Equal(t, first.ChainOK, result.ChainOK, "run %d: ChainOK must be identical across repeated calls on the same bundle bytes", i)
	}
}

func TestVerifyBundleSetOneTamperedRecordFailsWholeSet(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle := buildSetBundle(t, kp)
	records := bundle["records"].([]interface{})
	rec1 := records[1].(map[string]interface{})
	inner := rec1["record"].(map[string]interface{})
	inner["record_pb_b64"] = base64.RawURLEncoding.EncodeToString([]byte("tampered"))

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ExitCode)
	assert.Equal(t, SetIncomplete, result.SetStatus)

	var sawTampered bool
	for _, r := range result.Records {
		if r.RecordID == "r1" {
			assert.Equal(t, StatusTampered, r.Status)
			sawTampered = true
		}
	}
	assert.True(t, sawTampered)
}

// TestVerifyBundleSetInnerChainVacuousMatchFailsClosed is the multi-root
// regression for i-9e8c: root-0's own root_hash_b64 and root-1's
// prev_root_hash_b64 are both stripped, so the inner chain-walk's
// prevHash/nextPrevHash comparison sees "" on both sides. Before the fix
// this vacuously "matched" (ChainOK); it must now fail closed. Stripping
// root-0's root_hash_b64 also breaks its own records' Merkle proofs (an
// inherent consequence of the scenario, not incidental), so this test
// asserts only on ChainOK/ExitCode, not on which other checks also fail.
func TestVerifyBundleSetInnerChainVacuousMatchFailsClosed(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle := buildSetBundle(t, kp)

	signedRoots := bundle["signed_roots"].(map[string]interface{})
	root0 := signedRoots["root-0"].(map[string]interface{})
	root1 := signedRoots["root-1"].(map[string]interface{})
	delete(root0, "root_hash_b64")
	signRoot(t, kp, root0)
	delete(root1, "prev_root_hash_b64")
	signRoot(t, kp, root1)

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{})
	require.NoError(t, err)
	assert.Equal(t, ChainFailed, result.ChainOK, "both sides of the hash-chain link absent must not vacuously match")
	assert.NotEqual(t, 0, result.ExitCode)
}

func TestVerifyBundleFloorOKNilCausesExitCodeOne(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	signedRoot := bundle["signed_root"].(map[string]interface{})
	retentionPolicy := signedRoot["retention_policy"].(map[string]interface{})
	retentionPolicy["mode"] = "not-a-real-mode" // unparseable: AuthorizedFloor's default case errors
	// retention_policy is part of SignableRootFields, so it must be re-signed.
	signRoot(t, kp, signedRoot)

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.NoError(t, err)
	require.Nil(t, result.FloorOK, "callers must treat nil as a failure, never as a silent pass")
	assert.Equal(t, 1, result.ExitCode)
}

func TestVerifyBundleSetRequiredAnchorAbsentFails(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle := buildSetBundle(t, kp)
	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{
		RequireAnchor: RequireAnchor{Immudb: true},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ExitCode, "no root carries an immudb anchor, but --require-anchor immudb demands one")
	// Pin the failure to the anchor requirement specifically, not merely
	// "some other check happens to also fail" -- the base bundle otherwise
	// verifies cleanly (exit 0), so ImmudbResult is what must carry the fail.
	require.NotNil(t, result.ImmudbResult)
	assert.Equal(t, AnchorFailed, result.ImmudbResult.Status)
}

func TestVerifyBundleSetRequiredAnchorMissingMapFails(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle := buildSetBundle(t, kp)
	delete(bundle, "anchor_refs_by_root")
	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{
		RequireAnchor: RequireAnchor{Immudb: true},
	})
	require.NoError(t, err)
	assert.NotEqual(t, 0, result.ExitCode, "anchor_refs_by_root absent entirely must not bypass --require-anchor immudb")
	require.NotNil(t, result.ImmudbResult)
	assert.Equal(t, AnchorFailed, result.ImmudbResult.Status)
}

// TestVerifyBundleSetRequiredAnchorNonMapEntryFails gives root-1 a genuinely
// valid, verifiable immudb anchor so the only way this bundle can fail
// --require-anchor immudb is via root-0's requirement, whose
// anchor_refs_by_root entry is a non-map (null) value. A naive fix that
// merely iterates signed_roots but still `continue`s past non-map entries
// (rather than treating them as an absent-but-required anchor) would let
// this pass incorrectly, since root-1 alone satisfies "some root verified".
func TestVerifyBundleSetRequiredAnchorNonMapEntryFails(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle := buildSetBundle(t, kp)
	signedRoots := bundle["signed_roots"].(map[string]interface{})
	root1 := signedRoots["root-1"].(map[string]interface{})
	params := defaultImmudbFixtureParams(t)
	params.rootID = "root-1"
	params.signedRoot = root1
	immudbFx := buildImmudbFixture(t, kp, params)
	bundle["anchor_refs_by_root"] = map[string]interface{}{
		"root-0": nil,
		"root-1": anchorRefsWithImmudb(immudbFx),
	}
	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{
		ImmudbPublicKey: kp.pub,
		RequireAnchor:   RequireAnchor{Immudb: true},
	})
	require.NoError(t, err)
	assert.NotEqual(t, 0, result.ExitCode, "root-0's non-map anchor_refs_by_root entry must not bypass --require-anchor immudb even though root-1 verifies")
}

// TestVerifyBundleSetMixedAnchorCoverageReportsPartial is the regression for
// i-5fbz: when one root in a set bundle carries a genuinely verified immudb
// anchor and another carries none at all, the top-level ImmudbResult must not
// read as full coverage -- its Detail must say so explicitly (N of M roots),
// not silently pick one root's result as if it spoke for the whole bundle.
func TestVerifyBundleSetMixedAnchorCoverageReportsPartial(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle := buildSetBundle(t, kp)
	signedRoots := bundle["signed_roots"].(map[string]interface{})
	root0 := signedRoots["root-0"].(map[string]interface{})
	params := defaultImmudbFixtureParams(t)
	params.rootID = "root-0"
	params.signedRoot = root0
	immudbFx := buildImmudbFixture(t, kp, params)
	bundle["anchor_refs_by_root"] = map[string]interface{}{
		"root-0": anchorRefsWithImmudb(immudbFx),
		"root-1": map[string]interface{}{}, // no anchor at all
	}

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_200_000, Options{ImmudbPublicKey: kp.pub})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode, "no --require-anchor was set, so a skipped root must not fail the bundle")
	require.NotNil(t, result.ImmudbResult)
	assert.Equal(t, AnchorVerified, result.ImmudbResult.Status)
	assert.Contains(t, result.ImmudbResult.Detail, "1 of 2", "must not claim full coverage when only 1 of 2 roots is actually anchored")
	assert.NotContains(t, result.ImmudbResult.Detail, "all 2")
}

func TestSignableRootFieldsExactAllowlist(t *testing.T) {
	t.Parallel()

	assert.ElementsMatch(t, []string{
		"root_hash_b64", "tree_size", "partition", "partition_count", "covered_range",
		"prev_root_hash_b64", "prev_root_id", "notary_ts_from", "notary_ts_to", "retention_policy",
	}, SignableRootFields)
}

func TestAnchorCommandsForAllTypes(t *testing.T) {
	t.Parallel()

	anchorRefs := normalizeJSON(t, map[string]interface{}{
		"immudb": map[string]interface{}{"database": "defaultdb", "tx_id": 7, "tx_hash": "abc", "inclusion_proof": []interface{}{"a", "b"}},
		"s3":     map[string]interface{}{"bucket": "audit-roots", "key": "roots/0/x.json", "version_id": "v1"},
	})
	cmds := anchorCommandsFor(anchorRefs)
	assert.Contains(t, cmds["immudb"], "defaultdb")
	assert.Contains(t, cmds["immudb"], "tx_hash=abc inclusion_proof_len=2")
	assert.Contains(t, cmds["s3"], "audit-roots/roots/0/x.json")
	assert.Contains(t, cmds["s3"], "--version-id v1")
}

func TestVerifyMerkleInclusionLeafIndexOutOfRange(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	rec := buildRecordFixture(t, kp, "rec")
	other := recordFixture{leafHash: LeafHash([]byte("other"))}
	notaryTs := int64(1_700_000_000_000)
	tree := buildPositionedTree(t, []positionedLeaf{{leafHash: rec.leafHash, offset: 0}, {leafHash: other.leafHash, offset: 1}}, 0, notaryTs)
	signedRoot := normalizeJSON(t, map[string]interface{}{
		"root_hash_b64": rootHashFixture(t, tree),
		"tree_size":     2,
		"partition":     0,
		"notary_ts_to":  notaryTs,
	})
	merkleProof := merkleProofFixture(t, tree, 0, 0)
	merkleProof["leaf_index"] = json.Number("5") // out of [0, tree_size)
	assert.False(t, VerifyMerkleInclusion(rec.leafHash, signedRoot, merkleProof))
}

// TestVerifyMerkleInclusionLeafIndexNegative is the negative-side twin of
// TestVerifyMerkleInclusionLeafIndexOutOfRange -- VerifyMerkleInclusion's
// bounds check is `leafIndex < 0 || leafIndex >= treeSize`; only the high
// side had bundle-layer coverage (merkle.go's own unit tests cover the low
// side only at the InclusionProof-primitive layer, not through the bundle
// map path).
func TestVerifyMerkleInclusionLeafIndexNegative(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	rec := buildRecordFixture(t, kp, "rec")
	other := recordFixture{leafHash: LeafHash([]byte("other"))}
	notaryTs := int64(1_700_000_000_000)
	tree := buildPositionedTree(t, []positionedLeaf{{leafHash: rec.leafHash, offset: 0}, {leafHash: other.leafHash, offset: 1}}, 0, notaryTs)
	signedRoot := normalizeJSON(t, map[string]interface{}{
		"root_hash_b64": rootHashFixture(t, tree),
		"tree_size":     2,
		"partition":     0,
		"notary_ts_to":  notaryTs,
	})
	merkleProof := merkleProofFixture(t, tree, 0, 0)
	merkleProof["leaf_index"] = json.Number("-1")
	assert.False(t, VerifyMerkleInclusion(rec.leafHash, signedRoot, merkleProof))
}

func TestBundleAuditPathRejectsInvalidSide(t *testing.T) {
	t.Parallel()

	_, err := bundleAuditPath([]interface{}{
		map[string]interface{}{"hash_b64": base64.RawURLEncoding.EncodeToString(LeafHash([]byte("x"))), "side": "sideways"},
	})
	assert.Error(t, err)
}

// TestVerifyMerkleInclusionHandConstructedAuditPath builds a 2-leaf tree's
// node hashes directly from the primitives (leafNodeHash/nodeHash), never
// calling BuildTree or InclusionProof, and hand-writes the audit_path as
// literal "left"/"right" strings. This is deliberately independent of
// merkleProofFixture (which derives its "left"/"right" strings from
// InclusionProof's own Side output): every other bundle-level test in this
// package validates proof generation against proof verification, so a
// systematic left/right swap in either would be invisible to them. This
// test pins the expected root and both sibling positions by hand instead.
func TestVerifyMerkleInclusionHandConstructedAuditPath(t *testing.T) {
	t.Parallel()

	const partition, notaryTs = int64(0), int64(1_700_000_000_000)
	leaf0Pre := LeafHash([]byte("hand-leaf-A"))
	leaf1Pre := LeafHash([]byte("hand-leaf-B"))
	// The tree's actual leaf preimage is the *positioned* hash (Design D1),
	// not leaf0Pre/leaf1Pre directly -- see PositionedLeafHash.
	positioned0, err := PositionedLeafHash(partition, 0, 0, notaryTs, base64.RawURLEncoding.EncodeToString(leaf0Pre))
	require.NoError(t, err)
	positioned1, err := PositionedLeafHash(partition, 1, 1, notaryTs, base64.RawURLEncoding.EncodeToString(leaf1Pre))
	require.NoError(t, err)
	node0 := leafNodeHash(positioned0)
	node1 := leafNodeHash(positioned1)
	root := nodeHash(node0, node1)

	signedRoot := map[string]interface{}{
		"root_hash_b64": base64.RawURLEncoding.EncodeToString(root),
		"partition":     json.Number("0"),
		"notary_ts_to":  json.Number("1700000000000"),
	}

	// Leaf 0's sibling (leaf 1's node hash) sits on the right.
	proof0 := map[string]interface{}{
		"leaf_index": json.Number("0"),
		"offset":     json.Number("0"),
		"audit_path": []interface{}{
			map[string]interface{}{
				"hash_b64": base64.RawURLEncoding.EncodeToString(node1),
				"side":     "right",
			},
		},
	}
	assert.True(t, VerifyMerkleInclusion(leaf0Pre, signedRoot, proof0))

	// Leaf 1's sibling (leaf 0's node hash) sits on the left.
	proof1 := map[string]interface{}{
		"leaf_index": json.Number("1"),
		"offset":     json.Number("1"),
		"audit_path": []interface{}{
			map[string]interface{}{
				"hash_b64": base64.RawURLEncoding.EncodeToString(node0),
				"side":     "left",
			},
		},
	}
	assert.True(t, VerifyMerkleInclusion(leaf1Pre, signedRoot, proof1))

	// Swapping the hand-written side for leaf 0's proof (right -> left)
	// must break verification: this is the bundle-level analogue of
	// TestVerifyInclusionRejectsSideSwap, proving the "left"/"right" wire
	// strings are load-bearing rather than incidentally accepted.
	proof0Swapped := map[string]interface{}{
		"leaf_index": json.Number("0"),
		"offset":     json.Number("0"),
		"audit_path": []interface{}{
			map[string]interface{}{
				"hash_b64": base64.RawURLEncoding.EncodeToString(node1),
				"side":     "left",
			},
		},
	}
	assert.False(t, VerifyMerkleInclusion(leaf0Pre, signedRoot, proof0Swapped))
}

// TestPositionedLeafHashMatchesManualCanonicalJSON confirms PositionedLeafHash
// (Design D1) is exactly sha256 of the canonical JSON encoding of its five
// fields, independently reconstructed here via CanonicalJSONBytes directly
// rather than by calling PositionedLeafHash's own internals a second time.
func TestPositionedLeafHashMatchesManualCanonicalJSON(t *testing.T) {
	t.Parallel()

	content := LeafHash([]byte("hello"))
	contentB64 := base64.RawURLEncoding.EncodeToString(content)

	got, err := PositionedLeafHash(2, 42, 5, 1700000000000, contentB64)
	require.NoError(t, err)

	expectedPayload, err := CanonicalJSONBytes(map[string]interface{}{
		"partition":        json.Number("2"),
		"offset":           json.Number("42"),
		"index":            json.Number("5"),
		"notary_ts":        json.Number("1700000000000"),
		"content_hash_b64": contentB64,
	})
	require.NoError(t, err)
	want := LeafHash(expectedPayload)
	assert.Equal(t, want, got)
}

// TestVerifyMerkleInclusionFailsClosedWhenPositioningFieldsAbsent is the
// i-89e9 fail-closed regression: a bundle that cannot be positioned (missing
// merkle_proof.offset, signed_root.partition, or signed_root.notary_ts_to)
// must never fall back to hashing the bare leaf hash -- that would make the
// positioning check itself bypassable simply by omitting the new fields.
func TestVerifyMerkleInclusionFailsClosedWhenPositioningFieldsAbsent(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	rec := buildRecordFixture(t, kp, "rec")
	notaryTs := int64(1_700_000_000_000)
	tree := buildPositionedTree(t, []positionedLeaf{{leafHash: rec.leafHash, offset: 0}}, 0, notaryTs)
	fullSignedRoot := normalizeJSON(t, map[string]interface{}{
		"root_hash_b64": rootHashFixture(t, tree),
		"tree_size":     1,
		"partition":     0,
		"notary_ts_to":  notaryTs,
	})
	fullMerkleProof := merkleProofFixture(t, tree, 0, 0)
	require.True(t, VerifyMerkleInclusion(rec.leafHash, fullSignedRoot, fullMerkleProof), "sanity: fully-positioned proof must verify")

	missingOffset := merkleProofFixture(t, tree, 0, 0)
	delete(missingOffset, "offset")
	assert.False(t, VerifyMerkleInclusion(rec.leafHash, fullSignedRoot, missingOffset), "missing merkle_proof.offset must fail closed, not fall back to bare-leaf hashing")

	missingPartition := normalizeJSON(t, map[string]interface{}{
		"root_hash_b64": rootHashFixture(t, tree),
		"tree_size":     1,
		"notary_ts_to":  notaryTs,
	})
	assert.False(t, VerifyMerkleInclusion(rec.leafHash, missingPartition, fullMerkleProof), "missing signed_root.partition must fail closed")

	missingNotaryTs := normalizeJSON(t, map[string]interface{}{
		"root_hash_b64": rootHashFixture(t, tree),
		"tree_size":     1,
		"partition":     0,
	})
	assert.False(t, VerifyMerkleInclusion(rec.leafHash, missingNotaryTs, fullMerkleProof), "missing signed_root.notary_ts_to must fail closed")
}

// TestVerifyBundleTamperedOffsetFailsInclusionButSignatureStillVerifies is
// the i-89e9 end-to-end regression: Design D1 binds a record's Kafka offset
// into the actual Merkle tree leaf, so altering merkle_proof.offset after
// sealing -- without touching the record bytes or its signature -- must
// break Step 3's inclusion check even though the per-record signature
// (content-only, unaffected by D1) still verifies on its own.
func TestVerifyBundleTamperedOffsetFailsInclusionButSignatureStillVerifies(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	bundle, _ := singleRecordBundle(t, kp)
	merkleProof := bundle["merkle_proof"].(map[string]interface{})
	merkleProof["offset"] = json.Number("999") // was 0; record/signature untouched

	result, err := VerifyBundle(bundle, kp.pub, 1_700_000_000_000, Options{})
	require.NoError(t, err)
	require.Len(t, result.Records, 1)
	assert.Equal(t, StatusVerified, result.Records[0].Status, "per-record signature is content-only and must still verify")
	require.NotNil(t, result.Records[0].MerkleOK)
	assert.False(t, *result.Records[0].MerkleOK, "a record silently moved to a different offset must fail Step 3's positioned inclusion check")
	assert.NotEqual(t, 0, result.ExitCode)
}
