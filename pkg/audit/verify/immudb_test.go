//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sampleImmudbRootID is a fixed, arbitrary bundle root_id used by fixtures/
// tests below that don't care about the specific bound root -- only that
// VerifyImmudbAnchor's entry-hash check passes when the fixture and the
// verification call agree on the same root_id/signed_root.
const sampleImmudbRootID = "sample-root-id"

// sampleImmudbSignedRootFixture returns a fixed, arbitrary signed_root map
// paired with sampleImmudbRootID -- the (root_id, signed_root) pair
// buildImmudbFixture's default params bind the anchor's entry_hash to.
func sampleImmudbSignedRootFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	return normalizeJSON(t, map[string]interface{}{
		"root_hash_b64":      b64urlEnc(LeafHash([]byte("bundle-root"))),
		"tree_size":          1,
		"partition":          0,
		"covered_range":      map[string]interface{}{"from_seq": 1, "to_seq": 1},
		"prev_root_hash_b64": nil,
		"prev_root_id":       nil,
		"timestamp_ms":       1700000000000,
		"retention_policy":   map[string]interface{}{"mode": "retain-all"},
	})
}

// immudbFixtureParams are the raw (pre-JSON-normalization) transaction
// values a self-consistent immudb anchor fixture is built from.
type immudbFixtureParams struct {
	db         string
	txID       int64
	ts         int64
	version    int64
	nentries   int64
	blTxID     int64
	blRoot     []byte
	prevALH    []byte
	siblings   [][]byte
	rootID     string                 // bundle's root_id this anchor's entry_hash commits to
	signedRoot map[string]interface{} // bundle's signed_root this anchor's entry_hash commits to
}

func defaultImmudbFixtureParams(t *testing.T) immudbFixtureParams {
	return immudbFixtureParams{
		db:         "defaultdb",
		txID:       100,
		ts:         1700000000,
		version:    1,
		nentries:   3,
		blTxID:     50,
		blRoot:     LeafHash([]byte("bl-root")),
		prevALH:    LeafHash([]byte("prev-alh")),
		siblings:   [][]byte{LeafHash([]byte("sib1")), LeafHash([]byte("sib2"))},
		rootID:     sampleImmudbRootID,
		signedRoot: sampleImmudbSignedRootFixture(t),
	}
}

// buildImmudbFixture builds a self-consistent anchor_refs.immudb map: an
// entry_hash recomputed from p.rootID/p.signedRoot exactly as the notary
// commits it to the immudb HTree (expectedImmudbEntryHash), the HTree
// inclusion proof (entry_hash -> tx_eH), the ALH (tx_hash) recomputed from
// the header fields, and a genuine state signature over
// (db, tx_id, tx_hash).
func buildImmudbFixture(t *testing.T, kp testKeyPair, p immudbFixtureParams) map[string]interface{} {
	t.Helper()

	entryHash, err := expectedImmudbEntryHash(p.rootID, p.signedRoot)
	require.NoError(t, err)

	eH := entryHash
	for _, sib := range p.siblings {
		h := sha256.Sum256(concatBytes([]byte{immudbNodePrefix}, eH, sib))
		eH = h[:]
	}

	alh, err := ComputeImmudbALH(ImmudbALHFields{
		TxID: p.txID, PrevALH: p.prevALH, TS: p.ts, Version: p.version,
		Nentries: p.nentries, EH: eH, BlTxID: p.blTxID, BlRoot: p.blRoot,
	})
	require.NoError(t, err)

	statePayload, err := buildImmudbStatePayload(p.db, p.txID, alh)
	require.NoError(t, err)
	stateSig := kp.sign(statePayload)

	proof := make([]string, len(p.siblings))
	for i, sib := range p.siblings {
		proof[i] = base64.RawURLEncoding.EncodeToString(sib)
	}

	fixture := map[string]interface{}{
		"state_db":        p.db,
		"tx_id":           p.txID,
		"entry_hash":      base64.RawURLEncoding.EncodeToString(entryHash),
		"inclusion_proof": proof,
		"tx_nentries":     p.nentries,
		"tx_eH":           base64.RawURLEncoding.EncodeToString(eH),
		"tx_hash":         base64.RawURLEncoding.EncodeToString(alh),
		"state_signature": base64.RawURLEncoding.EncodeToString(stateSig),
		"tx_ts":           p.ts,
		"tx_version":      p.version,
		"tx_bl_tx_id":     p.blTxID,
		"tx_bl_root":      base64.RawURLEncoding.EncodeToString(p.blRoot),
		"tx_prev_alh":     base64.RawURLEncoding.EncodeToString(p.prevALH),
	}
	return normalizeJSON(t, fixture)
}

func anchorRefsWithImmudb(immudb map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"immudb": immudb}
}

func TestVerifyImmudbAnchorVerified(t *testing.T) {
	t.Parallel()

	for _, kpFn := range []func(*testing.T) testKeyPair{genEd25519KeyPair, genECDSAKeyPair} {
		kp := kpFn(t)
		params := defaultImmudbFixtureParams(t)
		immudb := buildImmudbFixture(t, kp, params)
		r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, params.signedRoot)
		require.Equal(t, AnchorVerified, r.Status, r.Detail)
	}
}

// TestVerifyImmudbAnchorBoundToDifferentRootFails is the core regression for
// the immudb entry-hash binding fix (i-4spt / spec s-16qk): a fully valid,
// self-consistent immudb anchor -- genuinely anchored to root A's own
// root_id/signed_root -- must FAIL when checked against a different root B.
// Earlier fixtures could not catch this since entry_hash/tx_eH/tx_hash were
// never bound to any particular bundle root.
func TestVerifyImmudbAnchorBoundToDifferentRootFails(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	immudb := buildImmudbFixture(t, kp, params)

	// Sanity: the fixture verifies cleanly against the root it's actually
	// bound to.
	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, params.signedRoot)
	require.Equal(t, AnchorVerified, r.Status, r.Detail)

	otherRootID := "a-different-root-id"
	otherSignedRoot := normalizeJSON(t, map[string]interface{}{
		"root_hash_b64":      b64urlEnc(LeafHash([]byte("a-different-bundle-root"))),
		"tree_size":          1,
		"partition":          0,
		"covered_range":      map[string]interface{}{"from_seq": 1, "to_seq": 1},
		"prev_root_hash_b64": nil,
		"prev_root_id":       nil,
		"timestamp_ms":       1700000000000,
		"retention_policy":   map[string]interface{}{"mode": "retain-all"},
	})
	r = VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, otherRootID, otherSignedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
	assert.Contains(t, r.Detail, "entry_hash_invalid")
}

// TestVerifyImmudbAnchorMissingRootIDFailsClosed exercises a genuine anchor
// (real entry_hash, real inclusion proof, real state signature, real ALH
// binding) verified when the caller has no bundle root_id available. Must
// fail closed, not read as "some anchor exists, so it's fine" -- an absent
// trusted input must not silently downgrade to skipped.
func TestVerifyImmudbAnchorMissingRootIDFailsClosed(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	immudb := buildImmudbFixture(t, kp, params)

	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, "", params.signedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
	assert.Contains(t, r.Detail, "entry_hash_invalid")
}

// TestVerifyImmudbAnchorMissingSignedRootFailsClosed is
// TestVerifyImmudbAnchorMissingRootIDFailsClosed's counterpart: root_id is
// available but signed_root is not. Must also fail closed.
func TestVerifyImmudbAnchorMissingSignedRootFailsClosed(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	immudb := buildImmudbFixture(t, kp, params)

	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, nil)
	assert.Equal(t, AnchorFailed, r.Status)
	assert.Contains(t, r.Detail, "entry_hash_invalid")
}

func TestVerifyImmudbAnchorAbsent(t *testing.T) {
	t.Parallel()

	r := VerifyImmudbAnchor(map[string]interface{}{}, nil, false, "", nil)
	assert.Equal(t, AnchorSkipped, r.Status)
}

func TestVerifyImmudbAnchorAbsentButRequired(t *testing.T) {
	t.Parallel()

	r := VerifyImmudbAnchor(map[string]interface{}{}, nil, true, "", nil)
	assert.Equal(t, AnchorFailed, r.Status)
}

func TestVerifyImmudbAnchorNoKeySkipped(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	immudb := buildImmudbFixture(t, kp, params)
	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), nil, false, params.rootID, params.signedRoot)
	assert.Equal(t, AnchorSkipped, r.Status)
}

func TestVerifyImmudbAnchorNoKeyButRequiredFails(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	immudb := buildImmudbFixture(t, kp, params)
	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), nil, true, params.rootID, params.signedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
}

func TestVerifyImmudbAnchorTamperedEntryHashFailsInclusion(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	immudb := buildImmudbFixture(t, kp, params)
	immudb["entry_hash"] = base64.RawURLEncoding.EncodeToString(LeafHash([]byte("evil")))
	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, params.signedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
	assert.Contains(t, r.Detail, "inclusion_proof_invalid")
}

func TestVerifyImmudbAnchorTamperedStateSignatureFails(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	other := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	immudb := buildImmudbFixture(t, kp, params)
	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), other.pub, false, params.rootID, params.signedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
	assert.Contains(t, r.Detail, "state_signature_invalid")
}

func TestVerifyImmudbAnchorTamperedPrevALHFailsBinding(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	immudb := buildImmudbFixture(t, kp, params)
	// tx_prev_alh no longer matches what tx_hash was actually computed from,
	// so the ALH-binding recomputation must fail even though the inclusion
	// proof and state signature (over the untouched tx_hash) still verify.
	immudb["tx_prev_alh"] = base64.RawURLEncoding.EncodeToString(LeafHash([]byte("different-prev-alh")))
	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, params.signedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
	assert.Contains(t, r.Detail, "alh_binding_invalid")
}

// TestVerifyImmudbAnchorALHFieldTamperMatrix flips each individual field
// bound into the ALH's inner hash (see immudbInnerHash) one at a time and
// confirms the binding recomputation notices -- tx_prev_alh alone is covered
// above (TestVerifyImmudbAnchorTamperedPrevALHFailsBinding); this closes the
// remaining fields (tx_id, tx_ts, tx_version, tx_bl_tx_id, tx_bl_root,
// tx_nentries) so no bound field could be silently ignored by the
// recomputation.
func TestVerifyImmudbAnchorALHFieldTamperMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(immudb map[string]interface{})
		// alsoState is true when the tampered field is also covered by the
		// state-signature payload (db, tx_id, tx_hash), so state_signature
		// must fail too, not just alh_binding.
		alsoState bool
	}{
		// Values are json.Number, matching how normalizeJSON (DecodeBundle)
		// actually decodes them -- a raw Go int64 here would make
		// getInt64Loose treat the field as absent (wrong type) and fail
		// closed for that reason instead of exercising genuine ALH
		// recomputation mismatch.
		{"tx_id", func(m map[string]interface{}) { m["tx_id"] = json.Number("999") }, true},
		{"tx_ts", func(m map[string]interface{}) { m["tx_ts"] = json.Number("1") }, false},
		{"tx_version", func(m map[string]interface{}) { m["tx_version"] = json.Number("0") }, false},
		{"tx_bl_tx_id", func(m map[string]interface{}) { m["tx_bl_tx_id"] = json.Number("999") }, false},
		{"tx_bl_root", func(m map[string]interface{}) {
			m["tx_bl_root"] = base64.RawURLEncoding.EncodeToString(LeafHash([]byte("different-bl-root")))
		}, false},
		{"tx_nentries", func(m map[string]interface{}) { m["tx_nentries"] = json.Number("4") }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			kp := genEd25519KeyPair(t)
			params := defaultImmudbFixtureParams(t)
			immudb := buildImmudbFixture(t, kp, params)
			c.mutate(immudb)
			r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, params.signedRoot)
			assert.Equal(t, AnchorFailed, r.Status)
			assert.Contains(t, r.Detail, "alh_binding_invalid", "field %s must be bound into the ALH", c.name)
			if c.alsoState {
				assert.Contains(t, r.Detail, "state_signature_invalid", "field %s is also covered by the state-signature payload", c.name)
			} else {
				assert.NotContains(t, r.Detail, "state_signature_invalid", "field %s is not covered by the state-signature payload", c.name)
			}
			assert.NotContains(t, r.Detail, "inclusion_proof_invalid", "field %s must not affect the (unrelated) inclusion proof", c.name)
		})
	}
}

// TestVerifyImmudbAnchorALHFieldTamperVersion0 repeats the tx_nentries case
// under header version 0, which folds nentries into the inner hash via the
// 2-byte-short encoding path (immudbInnerHash's v0 branch) rather than
// version 1's [mdLen || metadata || nentries(4BE)] path -- a regression here
// would only be caught by exercising the v0 branch specifically.
func TestVerifyImmudbAnchorALHFieldTamperVersion0(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	params.version = 0
	immudb := buildImmudbFixture(t, kp, params)
	immudb["tx_nentries"] = json.Number("4")
	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, params.signedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
	assert.Contains(t, r.Detail, "alh_binding_invalid")
}

// TestVerifyImmudbAnchorTamperedStateDBFails proves state_db is itself part
// of the signed state payload, not just tx_id/tx_hash: changing it (with a
// genuine key, genuine tx_hash) must break the state-signature check even
// though the ALH binding recomputation -- which does not read state_db --
// still succeeds.
func TestVerifyImmudbAnchorTamperedStateDBFails(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	immudb := buildImmudbFixture(t, kp, params)
	immudb["state_db"] = "a-different-database"
	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, params.signedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
	assert.Contains(t, r.Detail, "state_signature_invalid")
	assert.NotContains(t, r.Detail, "alh_binding_invalid")
}

// TestVerifyImmudbAnchorTamperedSiblingFailsInclusion tampers one HTree
// audit-path sibling (as opposed to entry_hash itself, already covered by
// TestVerifyImmudbAnchorTamperedEntryHashFailsInclusion) and confirms the
// recomputed root no longer matches tx_eH.
func TestVerifyImmudbAnchorTamperedSiblingFailsInclusion(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	immudb := buildImmudbFixture(t, kp, params)
	proof, ok := immudb["inclusion_proof"].([]interface{})
	require.True(t, ok)
	require.NotEmpty(t, proof)
	proof[0] = base64.RawURLEncoding.EncodeToString(LeafHash([]byte("evil-sibling")))
	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, params.signedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
	assert.Contains(t, r.Detail, "inclusion_proof_invalid")
}

func TestVerifyImmudbAnchorPartialProofFailsClosed(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	params := defaultImmudbFixtureParams(t)
	immudb := buildImmudbFixture(t, kp, params)
	// Strip the inclusion-proof/ALH-binding fields but leave a genuine
	// state_signature -- a partial proof must not read as a pass.
	delete(immudb, "tx_eH")
	delete(immudb, "entry_hash")
	r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, params.signedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
	assert.Contains(t, r.Detail, "incomplete")
}

// TestVerifyImmudbAnchorMalformedBase64FailsClosed injects a string that
// fails b64Decode outright (as opposed to a well-formed base64 value
// encoding the wrong bytes, already covered by e.g.
// TestVerifyImmudbAnchorTamperedEntryHashFailsInclusion and
// TestVerifyImmudbAnchorTamperedPrevALHFailsBinding) into each bundle field
// VerifyImmudbInclusion/VerifyImmudbALHBinding/VerifyImmudbEntryHash decode,
// and confirms the anchor fails closed rather than panicking or silently
// passing.
func TestVerifyImmudbAnchorMalformedBase64FailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		field           string
		wantDetailParts []string
	}{
		{"entry_hash", []string{"inclusion_proof_invalid", "entry_hash_invalid"}},
		{"tx_eH", []string{"inclusion_proof_invalid", "alh_binding_invalid"}},
		{"tx_bl_root", []string{"alh_binding_invalid"}},
		{"tx_prev_alh", []string{"alh_binding_invalid"}},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			t.Parallel()

			kp := genEd25519KeyPair(t)
			params := defaultImmudbFixtureParams(t)
			immudb := buildImmudbFixture(t, kp, params)
			immudb[c.field] = invalidBase64
			r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, params.signedRoot)
			assert.Equal(t, AnchorFailed, r.Status)
			for _, part := range c.wantDetailParts {
				assert.Contains(t, r.Detail, part, "field %s", c.field)
			}
		})
	}
}

func TestVerifyImmudbInclusionSingleEntryEmptyProof(t *testing.T) {
	t.Parallel()

	entryHash := LeafHash([]byte("solo"))
	assert.True(t, VerifyImmudbInclusion(entryHash, nil, 1, entryHash))
	assert.False(t, VerifyImmudbInclusion(entryHash, nil, 2, entryHash), "empty proof is only valid for nentries==1")
}

// independentHTreeLeaf/independentHTreeNode are a from-scratch
// reimplementation of immudb's embedded/htree domain separation
// (LeafPrefix=0x00, NodePrefix=0x01), written directly in this test rather
// than calling any function in this package -- so this test is an
// independent oracle, not a tautology against VerifyImmudbInclusion's own
// (previously broken) fold.
func independentHTreeLeaf(digest []byte) []byte {
	h := sha256.Sum256(append([]byte{0x00}, digest...))
	return h[:]
}

func independentHTreeNode(left, right []byte) []byte {
	b := append([]byte{0x01}, left...)
	b = append(b, right...)
	h := sha256.Sum256(b)
	return h[:]
}

// TestVerifyImmudbInclusionGoldenRegression is the direct regression for the
// missing-NodePrefix bug: VerifyImmudbInclusion's internal-node fold used to
// omit immudb's real 0x01 domain-separator byte, so it silently computed a
// different root than real immudb for any tree with more than one leaf (see
// embedded/htree.VerifyInclusion, byte-verified against codenotary/immudb
// v1.9.7). Every other fixture in this file builds its own expected eH via
// buildImmudbFixture, which used the exact same (once-broken) fold -- so
// none of them could have caught a regression back to it. This test builds
// a genuine 3-leaf HTree (exercising both an ordinary pair-fold and RFC
// 6962-style odd-count promotion) using independentHTreeLeaf/Node above,
// entirely independent of VerifyImmudbInclusion's own implementation.
func TestVerifyImmudbInclusionGoldenRegression(t *testing.T) {
	t.Parallel()

	d0 := []byte("digest-0")
	d1 := []byte("digest-1")
	d2 := []byte("digest-2")

	l0 := independentHTreeLeaf(d0)
	l1 := independentHTreeLeaf(d1)
	l2 := independentHTreeLeaf(d2)

	// level 0: [l0, l1, l2] (odd count: l2 is promoted unchanged)
	n01 := independentHTreeNode(l0, l1)
	// level 1: [n01, l2]
	root := independentHTreeNode(n01, l2)

	// entryHash is leaf index 0 (l0); its bottom-up audit path is [l1, l2].
	proof := []string{b64urlEnc(l1), b64urlEnc(l2)}

	require.True(t, VerifyImmudbInclusion(l0, proof, 3, root),
		"a genuine, independently-computed 3-leaf immudb HTree proof must verify")

	assert.False(t, VerifyImmudbInclusion(l0, proof, 3, independentHTreeLeaf([]byte("wrong-root"))),
		"must not verify against a root the proof doesn't actually fold to")
	tamperedProof := []string{b64urlEnc(independentHTreeLeaf([]byte("evil"))), b64urlEnc(l2)}
	assert.False(t, VerifyImmudbInclusion(l0, tamperedProof, 3, root),
		"must not verify with a tampered sibling")
}

// TestComputeImmudbALHRejectsNegativeTxFields is the direct regression for
// i-8szv: longToBEBytes documents that callers only ever pass non-negative
// transaction ids, but ComputeImmudbALH fed attacker-controlled tx_id/
// tx_bl_tx_id (read straight off the bundle) into it with no explicit check.
// Both fields must now be rejected with a clear error before reaching
// longToBEBytes.
func TestComputeImmudbALHRejectsNegativeTxFields(t *testing.T) {
	t.Parallel()

	base := ImmudbALHFields{
		TxID: 1, PrevALH: LeafHash([]byte("prev")), TS: 1, Version: 1,
		Nentries: 1, EH: LeafHash([]byte("eh")), BlTxID: 1, BlRoot: LeafHash([]byte("bl")),
	}

	negTxID := base
	negTxID.TxID = -1
	_, err := ComputeImmudbALH(negTxID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tx_id")

	negBlTxID := base
	negBlTxID.BlTxID = -1
	_, err = ComputeImmudbALH(negBlTxID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tx_bl_tx_id")
}

// TestBuildImmudbStatePayloadRejectsNegativeTxID is the buildImmudbStatePayload
// half of the i-8szv regression: the ImmutableState signature payload also
// feeds tx_id into longToBEBytes.
func TestBuildImmudbStatePayloadRejectsNegativeTxID(t *testing.T) {
	t.Parallel()

	_, err := buildImmudbStatePayload("defaultdb", -1, LeafHash([]byte("hash")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tx_id")
}

// TestVerifyImmudbAnchorNegativeTxFieldsFailClosed proves the negative-tx_id/
// tx_bl_tx_id rejection is actually wired into VerifyImmudbAnchor's end-to-end
// path, not just the two helpers directly: a bundle asserting a negative
// tx_id or tx_bl_tx_id must fail closed rather than being silently
// reinterpreted as a two's-complement bit pattern.
func TestVerifyImmudbAnchorNegativeTxFieldsFailClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		mutate    func(immudb map[string]interface{})
		alsoState bool
	}{
		{"tx_id", func(m map[string]interface{}) { m["tx_id"] = json.Number("-1") }, true},
		{"tx_bl_tx_id", func(m map[string]interface{}) { m["tx_bl_tx_id"] = json.Number("-1") }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			kp := genEd25519KeyPair(t)
			params := defaultImmudbFixtureParams(t)
			immudb := buildImmudbFixture(t, kp, params)
			c.mutate(immudb)
			r := VerifyImmudbAnchor(anchorRefsWithImmudb(immudb), kp.pub, false, params.rootID, params.signedRoot)
			assert.Equal(t, AnchorFailed, r.Status)
			assert.Contains(t, r.Detail, "alh_binding_invalid", "field %s must fail the ALH recomputation", c.name)
			if c.alsoState {
				assert.Contains(t, r.Detail, "state_signature_invalid", "field %s is also covered by the state-signature payload", c.name)
			} else {
				assert.NotContains(t, r.Detail, "state_signature_invalid", "field %s is not covered by the state-signature payload", c.name)
			}
		})
	}
}

// TestExpectedImmudbEntryHashMatchesIndependentByteConstruction is the
// golden regression for the entry_hash formula fix (i-75rl/i-dvp6):
// expectedImmudbEntryHash's disproven predecessor,
// sha256(sha256(root_id)||sha256(value)), matched no real immudb. Every
// other fixture in this file derives its expected entry_hash FROM
// expectedImmudbEntryHash itself, so none would catch a regression back to
// that old formula. This test instead reconstructs immudb's real HTree leaf
// from raw bytes -- independent of expectedImmudbEntryHash's own internals
// -- and additionally pins the result against a golden hex digest computed
// out-of-band (Python, mirroring crypto.md's formula) for a fixed
// (root_id, signed_root) pair, so any future edit that silently reintroduces
// the old formula fails loudly.
func TestExpectedImmudbEntryHashMatchesIndependentByteConstruction(t *testing.T) {
	t.Parallel()

	signedRoot := normalizeJSON(t, map[string]interface{}{
		"root_hash_b64": "abc",
		"partition":     0,
	})
	value, err := CanonicalJSONBytes(selectKeys(signedRoot, SignableRootFields))
	require.NoError(t, err)
	require.Equal(t, `{"partition":0,"root_hash_b64":"abc"}`, string(value), "test fixture invariant: pins the exact bytes the golden digest below was computed over")

	got, err := expectedImmudbEntryHash(sampleImmudbRootID, signedRoot)
	require.NoError(t, err)

	// Manual, from-scratch reconstruction (byte-verified against
	// codenotary/immudb 1.11.0, i-dvp6):
	//   sha256(0x00 || sha256(uint16(mdLen=0) || uint16(kLen) ||
	//                          (0x00||root_id) || sha256(0x00||value)))
	valueHash := sha256.Sum256(append([]byte{0x00}, value...))
	key := append([]byte{0x00}, []byte(sampleImmudbRootID)...)
	mdLen := []byte{0x00, 0x00}
	kLen := []byte{0x00, byte(len(key))}
	inner := sha256.Sum256(concatBytes(mdLen, kLen, key, valueHash[:]))
	want := sha256.Sum256(concatBytes([]byte{0x00}, inner[:]))
	assert.Equal(t, want[:], got)

	// Golden digest for root_id="sample-root-id",
	// value=canonical_json({"partition":0,"root_hash_b64":"abc"}), computed
	// independently in Python from crypto.md's formula.
	assert.Equal(t, "e6c8525c754c2501896adfd01004e95ccf80a3319239b9cbf7b37a201c0c46b6", hex.EncodeToString(got))
}
