//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manetu/policyengine/pkg/audit/verify"
)

// TestCounterExampleBundleForMissingRecordRoundTrips is the s-3vlq decision-7
// acceptance criterion: a counter-example bundle for a step-8
// (record-existence) discrepancy is a genuine record-kind offline bundle,
// independently re-verifiable via mpe verify record -- here, directly
// against pkg/audit/verify (the same engine `mpe verify record` runs). With
// no "record" data (the record genuinely does not exist), the correct,
// honest verdict is UNVERIFIED-NOT-SEALED (exit 2) -- not a parse/structural
// rejection, and never a false VERIFIED.
func TestCounterExampleBundleForMissingRecordRoundTrips(t *testing.T) {
	kp := genTestKeyPair(t)
	b1 := buildBatch(t, kp, 0, 1, 0, 3, 1000, nil, nil)
	root := EnumeratedRoot{RootID: "root-0", Payload: b1.root}

	finding := Finding{
		Kind: "record-existence", Partition: 0, RootID: "root-0",
		Offset: int64Ptr(1), LeafIndex: int64Ptr(1), RecordID: b1.leaves[1].ID,
		Detail: "record is absent from accesslog but still inside the retention window",
	}
	anchorRefs := map[string]interface{}{"builtin": map[string]interface{}{"root_id": root.RootID}}

	bundle, err := BuildCounterExampleBundle(finding, root, nil, anchorRefs, nil)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "counter-example.json")
	require.NoError(t, WriteCounterExampleBundle(path, bundle))

	roundTripped := readBackBundle(t, path)

	result, err := verify.VerifyBundle(roundTripped, kp.pub, 2000, verify.Options{})
	require.NoError(t, err, "a counter-example bundle must be structurally accepted by mpe verify record, never a parse rejection")
	assert.Equal(t, 2, result.ExitCode, "a genuinely absent record must read as UNVERIFIED-NOT-SEALED, not VERIFIED and not a crash")
	require.Len(t, result.Records, 1)
	assert.Equal(t, verify.StatusUnverifiedNotSealed, result.Records[0].Status)
}

// TestCounterExampleBundleForBatchDensityMismatchRoundTrips covers the other
// pinpoint shape (a step-7 finding): the record itself is present and its
// own signature verifies, but with no merkle_proof to offer (the leaf-index
// is exactly what's untrusted), inclusion cannot be confirmed -- the bundle
// must still round-trip (no parse error) and correctly report tampering
// (never a false VERIFIED), which is the honest verdict for "this batch's
// claimed density does not match its anchor-fetched root".
func TestCounterExampleBundleForBatchDensityMismatchRoundTrips(t *testing.T) {
	kp := genTestKeyPair(t)
	b1 := buildBatch(t, kp, 0, 1, 0, 3, 1000, nil, nil)
	root := EnumeratedRoot{RootID: "root-0", Payload: b1.root}

	content := b1.contentHash[1]
	sig := ed25519.Sign(kp.priv, content)
	record := &RecordEnvelope{
		RecordPBB64:  b64urlEncode([]byte("irrelevant-for-this-test")),
		LeafHashB64:  b64urlEncode(content),
		SignatureB64: b64urlEncode(sig),
		KeyID:        "test-key",
		SigAlg:       "Ed25519",
	}
	// Note: record_pb_b64 above intentionally does NOT hash to
	// LeafHashB64 -- BuildCounterExampleBundle only carries what the scan
	// already fetched (the leaf's content-hash from /leaves, not the raw
	// record body, which record-existence's "found" path does not itself
	// return). This still exercises the structural round-trip and the
	// no-merkle-proof-offered path faithfully.

	finding := Finding{
		Kind: "batch-density", Partition: 0, RootID: "root-0",
		Detail: "recomputed Merkle root from /leaves does not match the anchor-fetched root_hash_b64",
	}
	anchorRefs := map[string]interface{}{"builtin": map[string]interface{}{"root_id": root.RootID}}

	bundle, err := BuildCounterExampleBundle(finding, root, nil, anchorRefs, record)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "counter-example-density.json")
	require.NoError(t, WriteCounterExampleBundle(path, bundle))
	roundTripped := readBackBundle(t, path)

	result, err := verify.VerifyBundle(roundTripped, kp.pub, 2000, verify.Options{})
	require.NoError(t, err, "a counter-example bundle must be structurally accepted by mpe verify record, never a parse rejection")
	assert.NotEqual(t, 0, result.ExitCode, "a batch-density counter-example must never read as a clean VERIFIED bundle")
}

func TestBuildCounterExampleBundleRejectsWrongKind(t *testing.T) {
	root := EnumeratedRoot{RootID: "root-0", Payload: map[string]interface{}{}}
	_, err := BuildCounterExampleBundle(Finding{Kind: "chain", RootID: "root-0"}, root, nil, nil, nil)
	assert.Error(t, err)
}

func TestBuildCounterExampleBundleEmbedsPrevSignedRootOnMatch(t *testing.T) {
	kp := genTestKeyPair(t)
	b1 := buildBatch(t, kp, 0, 1, 0, 2, 1000, nil, nil)
	rootHash1, _ := getString(b1.root, "root_hash_b64")
	b2 := buildBatch(t, kp, 0, 1, 2, 2, 2000, "root-0", rootHash1)

	finding := Finding{Kind: "record-existence", RootID: "root-1", Offset: int64Ptr(2), LeafIndex: int64Ptr(0), RecordID: "x"}
	bundle, err := BuildCounterExampleBundle(finding, EnumeratedRoot{RootID: "root-1", Payload: b2.root}, &EnumeratedRoot{RootID: "root-0", Payload: b1.root}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, b1.root, bundle["prev_signed_root"])
}

func int64Ptr(v int64) *int64 { return &v }

func readBackBundle(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	m, err := verify.DecodeBundle(data)
	require.NoError(t, err)
	return m
}
