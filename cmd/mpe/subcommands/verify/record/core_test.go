//
//  Copyright © Manetu Inc. All rights reserved.
//

package record

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	auditverify "github.com/manetu/policyengine/pkg/audit/verify"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// ---------------------------------------------------------------------------
// Bundle fixture construction (schema v1.0), built entirely from the
// exported pkg/audit/verify API -- exercising this CLI wrapper the same way
// an external consumer of the package would.
// ---------------------------------------------------------------------------

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func genKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func pemPublicKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func normalize(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	m, err := auditverify.DecodeBundle(data)
	require.NoError(t, err)
	return m
}

// buildPositionedLeafBundle builds a positioned-leaf Merkle tree over a
// single leaf at index 0 (Design D1: the tree's actual leaf preimage binds
// partition/offset/index/notary_ts to the record's content hash, not the
// bare leaf hash -- see auditverify.PositionedLeafHash) and returns the
// tree's root hash bytes and a merkle_proof map (leaf_index, offset,
// audit_path) for that leaf. partition and notaryTs must match the
// signed_root this proof is ultimately embedded under.
func buildPositionedLeafBundle(t *testing.T, leafHash []byte, partition, offset, notaryTs int64) (rootHash []byte, merkleProof map[string]interface{}) {
	t.Helper()
	positioned, err := auditverify.PositionedLeafHash(partition, offset, 0, notaryTs, b64(leafHash))
	require.NoError(t, err)
	tree := auditverify.BuildTree([][]byte{positioned})
	rootHash, err = auditverify.Root(tree)
	require.NoError(t, err)
	proof, err := auditverify.InclusionProof(tree, 0)
	require.NoError(t, err)
	auditPath := make([]interface{}, len(proof))
	for i, step := range proof {
		side := "right"
		if step.Side == auditverify.SideLeft {
			side = "left"
		}
		auditPath[i] = map[string]interface{}{"hash_b64": b64(step.Hash), "side": side}
	}
	merkleProof = normalize(t, map[string]interface{}{"leaf_index": 0, "offset": offset, "audit_path": auditPath})
	return rootHash, merkleProof
}

// buildVerifiedBundle returns a single-record bundle JSON that should
// verify cleanly (exit 0), and the PEM-encoded public key that verifies it.
func buildVerifiedBundle(t *testing.T) (bundleJSON []byte, pubPEM string) {
	t.Helper()
	pub, priv := genKeyPair(t)

	recordPB := []byte("access-record-1")
	leafHash := auditverify.LeafHash(recordPB)
	sig := ed25519.Sign(priv, leafHash)
	record := normalize(t, map[string]interface{}{
		"record_pb_b64": b64(recordPB),
		"integrity": map[string]interface{}{
			"leaf_hash_b64": b64(leafHash),
			"signature_b64": b64(sig),
			"key_id":        "test-key",
			"sig_alg":       "Ed25519",
		},
	})

	rootHash, merkleProof := buildPositionedLeafBundle(t, leafHash, 0, 0, 1_700_000_000_000)

	root := normalize(t, map[string]interface{}{
		"root_hash_b64":      b64(rootHash),
		"tree_size":          1,
		"partition":          0,
		"partition_count":    1,
		"covered_range":      map[string]interface{}{"from_seq": 0, "to_seq": 0},
		"prev_root_hash_b64": nil,
		"prev_root_id":       nil,
		"notary_ts_from":     1_700_000_000_000,
		"notary_ts_to":       1_700_000_000_000,
		"retention_policy":   map[string]interface{}{"mode": "retain-all"},
	})
	signable := map[string]interface{}{}
	for _, k := range auditverify.SignableRootFields {
		if v, ok := root[k]; ok {
			signable[k] = v
		}
	}
	payload, err := auditverify.CanonicalJSONBytes(signable)
	require.NoError(t, err)
	root["root_signature_b64"] = b64(ed25519.Sign(priv, payload))

	bundle := map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           "manetu-audit-verification-bundle",
			"schema_version": "2.0",
			"bundle_kind":    "record",
		},
		"record":       record,
		"merkle_proof": merkleProof,
		"signed_root":  root,
		"anchor_refs":  map[string]interface{}{},
	}
	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data, pemPublicKey(t, pub)
}

// buildRelativeRetentionBundle is like buildVerifiedBundle but uses a
// "relative" retention policy with a short window, so the retention-floor
// check's outcome flips depending on whether trustedNowMs is epoch-0 (floor
// goes deeply negative, so the old record timestamp always clears it) or a
// realistic current time (floor lands after the record's 2023 timestamp,
// tripping the floor warning). This lets tests observe which trustedNowMs
// value was actually used without depending on wall-clock time directly.
func buildRelativeRetentionBundle(t *testing.T) (bundleJSON []byte, pubPEM string) {
	t.Helper()
	pub, priv := genKeyPair(t)

	recordPB := []byte("access-record-1")
	leafHash := auditverify.LeafHash(recordPB)
	sig := ed25519.Sign(priv, leafHash)
	record := normalize(t, map[string]interface{}{
		"record_pb_b64": b64(recordPB),
		"integrity": map[string]interface{}{
			"leaf_hash_b64": b64(leafHash),
			"signature_b64": b64(sig),
			"key_id":        "test-key",
			"sig_alg":       "Ed25519",
		},
	})

	rootHash, merkleProof := buildPositionedLeafBundle(t, leafHash, 0, 0, 1_700_000_000_000)

	root := normalize(t, map[string]interface{}{
		"root_hash_b64":      b64(rootHash),
		"tree_size":          1,
		"partition":          0,
		"partition_count":    1,
		"covered_range":      map[string]interface{}{"from_seq": 0, "to_seq": 0},
		"prev_root_hash_b64": nil,
		"prev_root_id":       nil,
		"notary_ts_from":     1_700_000_000_000,
		"notary_ts_to":       1_700_000_000_000,
		"retention_policy":   map[string]interface{}{"mode": "relative", "P": "P1D"},
	})
	signable := map[string]interface{}{}
	for _, k := range auditverify.SignableRootFields {
		if v, ok := root[k]; ok {
			signable[k] = v
		}
	}
	payload, err := auditverify.CanonicalJSONBytes(signable)
	require.NoError(t, err)
	root["root_signature_b64"] = b64(ed25519.Sign(priv, payload))

	bundle := map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           "manetu-audit-verification-bundle",
			"schema_version": "2.0",
			"bundle_kind":    "record",
		},
		"record":       record,
		"merkle_proof": merkleProof,
		"signed_root":  root,
		"anchor_refs":  map[string]interface{}{},
	}
	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data, pemPublicKey(t, pub)
}

// buildUnparseableRetentionPolicyBundle is like buildVerifiedBundle but uses
// a retention_policy with an unknown mode, so AuthorizedFloor's default case
// errors and FloorOK comes back nil rather than true/false.
func buildUnparseableRetentionPolicyBundle(t *testing.T) (bundleJSON []byte, pubPEM string) {
	t.Helper()
	pub, priv := genKeyPair(t)

	recordPB := []byte("access-record-1")
	leafHash := auditverify.LeafHash(recordPB)
	sig := ed25519.Sign(priv, leafHash)
	record := normalize(t, map[string]interface{}{
		"record_pb_b64": b64(recordPB),
		"integrity": map[string]interface{}{
			"leaf_hash_b64": b64(leafHash),
			"signature_b64": b64(sig),
			"key_id":        "test-key",
			"sig_alg":       "Ed25519",
		},
	})

	rootHash, merkleProof := buildPositionedLeafBundle(t, leafHash, 0, 0, 1_700_000_000_000)

	root := normalize(t, map[string]interface{}{
		"root_hash_b64":      b64(rootHash),
		"tree_size":          1,
		"partition":          0,
		"partition_count":    1,
		"covered_range":      map[string]interface{}{"from_seq": 0, "to_seq": 0},
		"prev_root_hash_b64": nil,
		"prev_root_id":       nil,
		"notary_ts_from":     1_700_000_000_000,
		"notary_ts_to":       1_700_000_000_000,
		"retention_policy":   map[string]interface{}{"mode": "not-a-real-mode"},
	})
	signable := map[string]interface{}{}
	for _, k := range auditverify.SignableRootFields {
		if v, ok := root[k]; ok {
			signable[k] = v
		}
	}
	payload, err := auditverify.CanonicalJSONBytes(signable)
	require.NoError(t, err)
	root["root_signature_b64"] = b64(ed25519.Sign(priv, payload))

	bundle := map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           "manetu-audit-verification-bundle",
			"schema_version": "2.0",
			"bundle_kind":    "record",
		},
		"record":       record,
		"merkle_proof": merkleProof,
		"signed_root":  root,
		"anchor_refs":  map[string]interface{}{},
	}
	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data, pemPublicKey(t, pub)
}

// buildTamperedBundle returns a verified bundle with the record bytes
// flipped after signing, without re-signing -- must fail leaf-hash
// recomputation (exit 1).
func buildTamperedBundle(t *testing.T) (bundleJSON []byte, pubPEM string) {
	t.Helper()
	data, pubPEM := buildVerifiedBundle(t)
	var bundle map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &bundle))
	record := bundle["record"].(map[string]interface{})
	record["record_pb_b64"] = b64([]byte("tampered-record!!"))
	out, err := json.Marshal(bundle)
	require.NoError(t, err)
	return out, pubPEM
}

// buildUnsealedBundle returns a bundle whose batch root is validly signed,
// but whose record has no integrity envelope at all (a pre-enablement
// record swept into an otherwise-legitimate batch) -- exit 2.
func buildUnsealedBundle(t *testing.T) (bundleJSON []byte, pubPEM string) {
	t.Helper()
	pub, priv := genKeyPair(t)
	record := normalize(t, map[string]interface{}{
		"record_pb_b64": b64([]byte("pre-enablement-record")),
	})

	// The record has no integrity envelope, so VerifyMerkleInclusion is
	// never reached -- the tree/proof below only need to produce a
	// plausible, validly-signed root_hash_b64.
	rootHash, _ := buildPositionedLeafBundle(t, auditverify.LeafHash([]byte("some-other-sealed-record")), 0, 0, 1_700_000_000_000)

	root := normalize(t, map[string]interface{}{
		"root_hash_b64":      b64(rootHash),
		"tree_size":          1,
		"partition":          0,
		"partition_count":    1,
		"covered_range":      map[string]interface{}{"from_seq": 0, "to_seq": 0},
		"prev_root_hash_b64": nil,
		"prev_root_id":       nil,
		"notary_ts_from":     1_700_000_000_000,
		"notary_ts_to":       1_700_000_000_000,
		"retention_policy":   map[string]interface{}{"mode": "retain-all"},
	})
	signable := map[string]interface{}{}
	for _, k := range auditverify.SignableRootFields {
		if v, ok := root[k]; ok {
			signable[k] = v
		}
	}
	payload, err := auditverify.CanonicalJSONBytes(signable)
	require.NoError(t, err)
	root["root_signature_b64"] = b64(ed25519.Sign(priv, payload))

	bundle := map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           "manetu-audit-verification-bundle",
			"schema_version": "2.0",
			"bundle_kind":    "record",
		},
		"record":       record,
		"merkle_proof": map[string]interface{}{"leaf_index": 0, "audit_path": []interface{}{}},
		"signed_root":  root,
		"anchor_refs":  map[string]interface{}{},
	}
	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data, pemPublicKey(t, pub)
}

// beBytes big-endian-encodes n into a size-byte slice (2, 4, or 8).
func beBytes(n int64, size int) []byte {
	b := make([]byte, size)
	switch size {
	case 2:
		binary.BigEndian.PutUint16(b, uint16(n))
	case 4:
		binary.BigEndian.PutUint32(b, uint32(n))
	case 8:
		binary.BigEndian.PutUint64(b, uint64(n))
	default:
		panic("beBytes: unsupported size")
	}
	return b
}

// buildImmudbALH replicates immudb's Accumulator Linear Hash construction
// (documented on pkg/audit/verify.ComputeImmudbALH) independently, using
// only stdlib primitives, to keep this CLI test suite decoupled from that
// package's own internal helper (immudbInnerHash remains unexported) rather
// than because ComputeImmudbALH itself is unreachable -- its parameter
// type, ImmudbALHFields, is now exported:
//
//	Alh = sha256(txID(8BE) || prevAlh(32) || innerHash(32))
//
// where innerHash = sha256(ts(8BE) || version(2BE) || mdLen(2BE)=0 ||
// nentries(4BE) || eH(32) || blTxID(8BE) || blRoot(32)) -- the version-1,
// no-metadata layout.
func buildImmudbALH(txID, ts, version, nentries, blTxID int64, eH, blRoot, prevALH []byte) []byte {
	var inner []byte
	inner = append(inner, beBytes(ts, 8)...)
	inner = append(inner, beBytes(version, 2)...)
	inner = append(inner, beBytes(0, 2)...) // mdLen: no metadata
	inner = append(inner, beBytes(nentries, 4)...)
	inner = append(inner, eH...)
	inner = append(inner, beBytes(blTxID, 8)...)
	inner = append(inner, blRoot...)
	innerHash := sha256.Sum256(inner)

	var alhInput []byte
	alhInput = append(alhInput, beBytes(txID, 8)...)
	alhInput = append(alhInput, prevALH...)
	alhInput = append(alhInput, innerHash[:]...)
	alh := sha256.Sum256(alhInput)
	return alh[:]
}

// buildImmudbStatePayload replicates the bytes immudb's server signs as its
// ImmutableState: [len(db)(4BE)][db bytes][tx_id(8BE)][tx_hash bytes].
func buildImmudbStatePayload(db string, txID int64, txHash []byte) []byte {
	var payload []byte
	payload = append(payload, beBytes(int64(len(db)), 4)...)
	payload = append(payload, []byte(db)...)
	payload = append(payload, beBytes(txID, 8)...)
	payload = append(payload, txHash...)
	return payload
}

// buildImmudbAnchoredBundle is like buildVerifiedBundle but also embeds a
// self-consistent anchor_refs.immudb (HTree inclusion proof, ALH, and a
// genuine state signature), signed by a fresh immudb keypair independent of
// the notary key -- for exercising the CLI's immudb output-rendering path
// (i-6v11) end-to-end via Run(). Unlike testdata/parity/*, this is a
// self-generated fixture (not a golden cross-implementation artifact
// captured from the real Clojure CLI + real notary/immudb signing keys, per
// parity_test.go's doc comment on that directory's provenance contract) --
// it exercises this package's own rendering logic, not cross-implementation
// parity.
func buildImmudbAnchoredBundle(t *testing.T) (bundleJSON []byte, pubPEM, immudbPubPEM string) {
	t.Helper()
	data, pubPEM := buildVerifiedBundle(t)
	immudbPub, immudbPriv := genKeyPair(t)

	// Decode via DecodeBundle (not encoding/json directly) so numeric
	// fields come back as json.Number -- the shape CanonicalJSONBytes
	// requires -- matching how a real caller would re-load this bundle.
	bundle, err := auditverify.DecodeBundle(data)
	require.NoError(t, err)
	signedRoot, ok := bundle["signed_root"].(map[string]interface{})
	require.True(t, ok)

	const rootID = "test-root-id-123"
	const db = "defaultdb"
	const txID, ts, version, nentries, blTxID = int64(100), int64(1_700_000_000), int64(1), int64(3), int64(50)
	blRoot := auditverify.LeafHash([]byte("bl-root"))
	prevALH := auditverify.LeafHash([]byte("prev-alh"))
	siblings := [][]byte{auditverify.LeafHash([]byte("sib1")), auditverify.LeafHash([]byte("sib2"))}

	// entry_hash = immudb's real HTree leaf over the (key, value) pair the
	// notary commits to the HTree as (key = the 0x00-prefixed store key
	// "\x00"+root_id, value = canonical_json_bytes(select_keys(signed_root,
	// SignableRootFields))) -- see pkg/audit/verify's
	// expectedImmudbEntryHash / notary/anchor/immudb.clj's append-root!, so
	// this bundle's own root_id/signed_root is what the anchor commits to
	// (i-4spt / s-16qk). Byte-verified against codenotary/immudb 1.11.0
	// (i-dvp6): sha256(0x00 || sha256(uint16(mdLen=0) || uint16(kLen) ||
	// (0x00||root_id) || sha256(0x00||value))).
	signable := map[string]interface{}{}
	for _, k := range auditverify.SignableRootFields {
		if v, ok := signedRoot[k]; ok {
			signable[k] = v
		}
	}
	valueBytes, err := auditverify.CanonicalJSONBytes(signable)
	require.NoError(t, err)
	valueHashSum := sha256.Sum256(append([]byte{0x00}, valueBytes...))
	key := append([]byte{0x00}, []byte(rootID)...)
	var innerInput []byte
	innerInput = append(innerInput, beBytes(0, 2)...)               // mdLen=0 (no metadata)
	innerInput = append(innerInput, beBytes(int64(len(key)), 2)...) // kLen
	innerInput = append(innerInput, key...)
	innerInput = append(innerInput, valueHashSum[:]...)
	innerSum := sha256.Sum256(innerInput)
	entryHashSum := sha256.Sum256(append([]byte{0x00}, innerSum[:]...))
	entryHash := entryHashSum[:]

	// Internal-node fold prepends immudb's NodePrefix=0x01 domain separator
	// (embedded/htree.VerifyInclusion), matching pkg/audit/verify's
	// VerifyImmudbInclusion.
	eH := entryHash
	for _, sib := range siblings {
		sum := sha256.Sum256(append(append([]byte{0x01}, eH...), sib...))
		eH = sum[:]
	}
	alh := buildImmudbALH(txID, ts, version, nentries, blTxID, eH, blRoot, prevALH)
	stateSig := ed25519.Sign(immudbPriv, buildImmudbStatePayload(db, txID, alh))

	proof := make([]interface{}, len(siblings))
	for i, sib := range siblings {
		proof[i] = b64(sib)
	}
	immudb := normalize(t, map[string]interface{}{
		"state_db":        db,
		"tx_id":           txID,
		"entry_hash":      b64(entryHash),
		"inclusion_proof": proof,
		"tx_nentries":     nentries,
		"tx_eH":           b64(eH),
		"tx_hash":         b64(alh),
		"state_signature": b64(stateSig),
		"tx_ts":           ts,
		"tx_version":      version,
		"tx_bl_tx_id":     blTxID,
		"tx_bl_root":      b64(blRoot),
		"tx_prev_alh":     b64(prevALH),
	})

	bundle["root_id"] = rootID
	bundle["anchor_refs"] = map[string]interface{}{"immudb": immudb}
	out, err := json.Marshal(bundle)
	require.NoError(t, err)
	return out, pubPEM, pemPublicKey(t, immudbPub)
}

// buildS3AnchoredBundle is like buildVerifiedBundle but also embeds a
// self-consistent anchor_refs.s3 (offline content_sha256 binding, no
// out-of-band key needed -- see pkg/audit/verify.VerifyS3Anchor), for
// exercising the CLI's s3 output-rendering path end-to-end via Run().
func buildS3AnchoredBundle(t *testing.T) (bundleJSON []byte, pubPEM string) {
	t.Helper()
	data, pubPEM := buildVerifiedBundle(t)

	bundle, err := auditverify.DecodeBundle(data)
	require.NoError(t, err)
	signedRoot, ok := bundle["signed_root"].(map[string]interface{})
	require.True(t, ok)

	// content_sha256 = sha256(canonical_json_bytes(select_keys(signed_root,
	// SignableRootFields))) -- the same canonical signable-fields encoding
	// immudb's entry_hash binds to (pkg/audit/verify's
	// expectedS3ContentSHA256 / notary/anchor/s3.clj's content-sha256), so
	// this bundle's own signed_root is what the anchor commits to.
	signable := map[string]interface{}{}
	for _, k := range auditverify.SignableRootFields {
		if v, ok := signedRoot[k]; ok {
			signable[k] = v
		}
	}
	valueBytes, err := auditverify.CanonicalJSONBytes(signable)
	require.NoError(t, err)
	contentSHA256 := sha256.Sum256(valueBytes)

	bundle["anchor_refs"] = map[string]interface{}{"s3": map[string]interface{}{
		"bucket":         "audit-roots",
		"key":            "roots/0/some-root-id.json",
		"version_id":     "v1",
		"content_sha256": base64.StdEncoding.EncodeToString(contentSHA256[:]),
	}}
	out, err := json.Marshal(bundle)
	require.NoError(t, err)
	return out, pubPEM
}

// buildSetBundleTwoRoots returns a two-record, two-root set bundle: record
// "rec-a" is sealed under root "root-a", record "rec-b" is sealed under root
// "root-b", chained via prev_root_hash_b64/prev_root_id. Both roots verify
// cleanly (exit 0), so the test can isolate the CLI's per-record display bug
// (root hash hints bleeding from one record onto another) from any
// verification-outcome bug.
func buildSetBundleTwoRoots(t *testing.T) (bundleJSON []byte, pubPEM string, rootHashA, rootHashB string) {
	t.Helper()
	pub, priv := genKeyPair(t)

	buildRecord := func(payload string) (record map[string]interface{}, leafHash []byte) {
		recordPB := []byte(payload)
		leafHash = auditverify.LeafHash(recordPB)
		sig := ed25519.Sign(priv, leafHash)
		record = normalize(t, map[string]interface{}{
			"record_pb_b64": b64(recordPB),
			"integrity": map[string]interface{}{
				"leaf_hash_b64": b64(leafHash),
				"signature_b64": b64(sig),
				"key_id":        "test-key",
				"sig_alg":       "Ed25519",
			},
		})
		return record, leafHash
	}
	signRoot := func(root map[string]interface{}) {
		signable := map[string]interface{}{}
		for _, k := range auditverify.SignableRootFields {
			if v, ok := root[k]; ok {
				signable[k] = v
			}
		}
		payload, err := auditverify.CanonicalJSONBytes(signable)
		require.NoError(t, err)
		root["root_signature_b64"] = b64(ed25519.Sign(priv, payload))
	}

	recordA, leafHashA := buildRecord("access-record-A")
	recordB, leafHashB := buildRecord("access-record-B")
	rootHashBytesA, merkleProofA := buildPositionedLeafBundle(t, leafHashA, 0, 0, 1_700_000_000_000)
	rootHashBytesB, merkleProofB := buildPositionedLeafBundle(t, leafHashB, 0, 1, 1_700_000_100_000)
	rootHashA = b64(rootHashBytesA)
	rootHashB = b64(rootHashBytesB)

	rootA := normalize(t, map[string]interface{}{
		"root_hash_b64":      rootHashA,
		"tree_size":          1,
		"partition":          0,
		"partition_count":    1,
		"covered_range":      map[string]interface{}{"from_seq": 0, "to_seq": 0},
		"prev_root_hash_b64": nil,
		"prev_root_id":       nil,
		"notary_ts_from":     1_700_000_000_000,
		"notary_ts_to":       1_700_000_000_000,
		"retention_policy":   map[string]interface{}{"mode": "retain-all"},
	})
	signRoot(rootA)

	rootB := normalize(t, map[string]interface{}{
		"root_hash_b64":      rootHashB,
		"tree_size":          1,
		"partition":          0,
		"partition_count":    1,
		"covered_range":      map[string]interface{}{"from_seq": 1, "to_seq": 1},
		"prev_root_hash_b64": rootHashA,
		"prev_root_id":       "root-a",
		"notary_ts_from":     1_700_000_100_000,
		"notary_ts_to":       1_700_000_100_000,
		"retention_policy":   map[string]interface{}{"mode": "retain-all"},
	})
	signRoot(rootB)

	records := []interface{}{
		map[string]interface{}{"record_id": "rec-a", "root_id": "root-a", "merkle_proof": merkleProofA, "record": recordA},
		map[string]interface{}{"record_id": "rec-b", "root_id": "root-b", "merkle_proof": merkleProofB, "record": recordB},
	}

	bundle := map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           "manetu-audit-verification-bundle",
			"schema_version": "2.0",
			"bundle_kind":    "set",
		},
		"records":      records,
		"signed_roots": map[string]interface{}{"root-a": rootA, "root-b": rootB},
		"anchor_refs_by_root": map[string]interface{}{
			"root-a": map[string]interface{}{},
			"root-b": map[string]interface{}{},
		},
		"completeness": map[string]interface{}{
			"from_seq":      0,
			"to_seq":        1,
			"total_records": 2,
			"contiguous":    true,
		},
	}
	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data, pemPublicKey(t, pub), rootHashA, rootHashB
}

func writeTempFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

// ---------------------------------------------------------------------------
// runCmd -- drives real cli.Command flag parsing (matching the pattern used
// by the other mpe subcommands' tests), then calls the testable Run()
// directly so exit codes can be asserted without an os.Exit subprocess.
// ---------------------------------------------------------------------------

// freshFlags returns copies of the package-level Flags so each runCmd call
// parses into its own flag instances -- urfave/cli/v3 flags carry parse
// state (e.g. IsSet) on the shared flag struct itself, so reusing Flags's
// pointers directly across calls would leak "was this flag set" state from
// one test's cmd.Run into the next.
func freshFlags() []cli.Flag {
	fresh := make([]cli.Flag, len(Flags))
	for i, f := range Flags {
		switch v := f.(type) {
		case *cli.StringFlag:
			cp := *v
			fresh[i] = &cp
		default:
			fresh[i] = f
		}
	}
	return fresh
}

func runCmd(t *testing.T, args []string) (exitCode int, stdout, stderr string) {
	t.Helper()
	var captured *cli.Command
	cmd := &cli.Command{
		Name:  "verify",
		Flags: freshFlags(),
		Action: func(_ context.Context, c *cli.Command) error {
			captured = c
			return nil
		},
	}
	require.NoError(t, cmd.Run(context.Background(), append([]string{"verify"}, args...)))

	var outBuf, errBuf bytes.Buffer
	code := Run(captured, &outBuf, &errBuf)
	return code, outBuf.String(), errBuf.String()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestRun_VerifiedBundleExitsZero(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "VERIFIED")
	require.Contains(t, stdout, "Root signature: OK")
	require.Contains(t, stdout, "Result set: complete")
}

func TestRun_TamperedBundleExitsOne(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildTamperedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 1, code)
	require.Contains(t, stdout, "TAMPERED")
}

func TestRun_UnsealedBundleExitsTwo(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildUnsealedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 2, code)
	require.Contains(t, stdout, "UNVERIFIED-NOT-SEALED")
}

func TestRun_WrongKeyExitsOne(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, _ := buildVerifiedBundle(t)
	wrongPub, _ := genKeyPair(t)
	wrongPubPEM := pemPublicKey(t, wrongPub)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(wrongPubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 1, code)
	require.Contains(t, stdout, "TAMPERED")
}

func TestRun_MissingPublicKeyExitsThree(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, _ := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)

	code, _, stderr := runCmd(t, []string{"--bundle", bundlePath})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "--public-key is required")
}

func TestRun_BadKeyPathExitsThree(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, _ := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)

	code, _, stderr := runCmd(t, []string{"--bundle", bundlePath, "--public-key", filepath.Join(dir, "nonexistent.pem")})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "failed to load public key")
}

// TestRun_OversizedBundleExitsThree exercises loadBundle's size cap
// (maxInputBytes) without constructing a real multi-hundred-MB fixture: it
// temporarily shrinks the cap so a small, otherwise-ordinary bundle trips it.
func TestRun_OversizedBundleExitsThree(t *testing.T) {
	dir := t.TempDir()
	bundleJSON, pubPEM := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	oldMax := maxInputBytes
	maxInputBytes = int64(len(bundleJSON)) - 1
	defer func() { maxInputBytes = oldMax }()

	code, _, stderr := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "exceeds")
}

// TestRun_OversizedKeyExitsThree is TestRun_OversizedBundleExitsThree's
// counterpart for loadPublicKeyFile's size cap.
func TestRun_OversizedKeyExitsThree(t *testing.T) {
	dir := t.TempDir()
	bundleJSON, pubPEM := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	oldMax := maxInputBytes
	maxInputBytes = int64(len(pubPEM)) - 1
	defer func() { maxInputBytes = oldMax }()

	code, _, stderr := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "exceeds")
}

func TestRun_MalformedBundleExitsThree(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, pubPEM := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", []byte("{not valid json"))
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, _, stderr := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 3, code)
	require.NotEmpty(t, stderr)
}

func TestRun_InvalidRequireAnchorTypeExitsThree(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, _, stderr := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath, "--require-anchor", "bogus"})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "invalid --require-anchor type")
}

// TestRun_RequireAnchorAbsentExitsOne guards against the CLI silently
// exiting 1 with an otherwise-clean-looking report (same failure mode as
// TestRun_UnparseableRetentionPolicyExitsOneWithExplanation, but for
// --require-anchor): the report must actually say why.
func TestRun_RequireAnchorAbsentExitsOne(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath, "--require-anchor", "immudb"})
	require.Equal(t, 1, code)
	require.Contains(t, stdout, "immudb anchor: FAILED")
	require.Contains(t, stdout, "required immudb anchor is absent from bundle")
}

// TestRun_BundleFromStdin exercises loadBundle's stdin branch (path == "" or
// "-"), which every other test bypasses by always passing --bundle a file
// path. This is also the first form shown in Usage()/verify.md's synopsis.
func TestRun_BundleFromStdin(t *testing.T) {
	dir := t.TempDir()
	bundleJSON, pubPEM := buildVerifiedBundle(t)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()
	go func() {
		_, _ = w.Write(bundleJSON)
		_ = w.Close()
	}()

	code, stdout, _ := runCmd(t, []string{"--public-key", keyPath})
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "VERIFIED")
}

// TestRun_ImmudbAnchorVerified is the regression for i-6v11: the immudb
// VERIFIED/FAILED CLI output rendering lines (output.go's immudb branch)
// were previously only exercised via the bad-key-path error case
// (TestRun_BadImmudbKeyPathExitsThree) -- never a genuinely valid anchor
// through Run() end-to-end.
func TestRun_ImmudbAnchorVerified(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM, immudbPubPEM := buildImmudbAnchoredBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))
	immudbKeyPath := writeTempFile(t, dir, "immudb-key.pem", []byte(immudbPubPEM))

	code, stdout, _ := runCmd(t, []string{
		"--bundle", bundlePath, "--public-key", keyPath,
		"--immudb-public-key", immudbKeyPath,
	})
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "immudb anchor: VERIFIED")
	require.Contains(t, stdout, "RESULT: OK (exit 0)")
}

// TestRun_ImmudbAnchorWrongKeyFailed mirrors TestRun_ImmudbAnchorVerified
// but checks against a different immudb public key than the one that
// actually signed the ImmutableState -- the anchor must fail closed.
func TestRun_ImmudbAnchorWrongKeyFailed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM, _ := buildImmudbAnchoredBundle(t)
	otherImmudbPub, _ := genKeyPair(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))
	immudbKeyPath := writeTempFile(t, dir, "immudb-key.pem", []byte(pemPublicKey(t, otherImmudbPub)))

	code, stdout, _ := runCmd(t, []string{
		"--bundle", bundlePath, "--public-key", keyPath,
		"--immudb-public-key", immudbKeyPath,
	})
	require.Equal(t, 1, code)
	require.Contains(t, stdout, "immudb anchor: FAILED")
	require.Contains(t, stdout, "RESULT: FAILED (exit 1)")
}

// TestRun_BadImmudbKeyPathExitsThree is TestRun_BadKeyPathExitsThree's
// counterpart for the optional --immudb-public-key flag: an unreadable path
// there is a distinct code branch (loadOptionalPublicKeyFile) from the
// required --public-key path and was previously untested.
func TestRun_BadImmudbKeyPathExitsThree(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, _, stderr := runCmd(t, []string{
		"--bundle", bundlePath, "--public-key", keyPath,
		"--immudb-public-key", filepath.Join(dir, "nonexistent-immudb.pem"),
	})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "failed to load immudb public key")
}

// TestRun_S3AnchorVerified exercises the CLI's s3 output-rendering path
// end-to-end via Run() -- unlike immudb/the retired rekor tier, s3 needs no
// --s3-public-key flag at all, since content_sha256 is a pure function of
// the bundle's own signed_root.
func TestRun_S3AnchorVerified(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildS3AnchoredBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "s3 anchor: VERIFIED")
	require.Contains(t, stdout, "RESULT: OK (exit 0)")
}

// TestRun_S3AnchorTamperedContentFailed mirrors TestRun_S3AnchorVerified but
// with a content_sha256 that no longer matches the bundle's own signed_root
// -- unlike immudb (which needs a wrong/absent key to fail), an s3 binding
// mismatch is checked -- and must fail -- unconditionally, since no key is
// involved at all.
func TestRun_S3AnchorTamperedContentFailed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildS3AnchoredBundle(t)
	var bundle map[string]interface{}
	require.NoError(t, json.Unmarshal(bundleJSON, &bundle))
	anchorRefs := bundle["anchor_refs"].(map[string]interface{})
	s3 := anchorRefs["s3"].(map[string]interface{})
	s3["content_sha256"] = base64.StdEncoding.EncodeToString([]byte("not-the-real-content-hash!!!!!!"))
	tampered, err := json.Marshal(bundle)
	require.NoError(t, err)

	bundlePath := writeTempFile(t, dir, "bundle.json", tampered)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 1, code)
	require.Contains(t, stdout, "s3 anchor: FAILED")
	require.Contains(t, stdout, "RESULT: FAILED (exit 1)")
}

// TestRun_RequireAnchorS3AbsentExitsOne is TestRun_RequireAnchorAbsentExitsOne's
// s3 counterpart.
func TestRun_RequireAnchorS3AbsentExitsOne(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath, "--require-anchor", "s3"})
	require.Equal(t, 1, code)
	require.Contains(t, stdout, "s3 anchor: FAILED")
	require.Contains(t, stdout, "required s3 anchor is absent from bundle")
}

// TestRun_RequireAnchorBothTypesExitsThree confirms parseRequireAnchor's
// exclusivity check (a root is anchored to exactly one backend) is actually
// wired into Run(), not just unit-tested in isolation.
func TestRun_RequireAnchorBothTypesExitsThree(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, _, stderr := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath, "--require-anchor", "immudb,s3"})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "cannot both be required")
}

// TestRun_SetBundlePerRecordHintsMatchOwnRoot exercises Run() end-to-end on
// a two-root set bundle and asserts each record's line shows its own root
// hash, not the other record's -- the bug this test guards against:
// formatRecordLine was called with a single bundle-global root result for
// every record.
func TestRun_SetBundlePerRecordHintsMatchOwnRoot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM, rootHashA, rootHashB := buildSetBundleTwoRoots(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "Result set: complete")

	require.NotEqual(t, rootHashA[:12], rootHashB[:12], "test fixture invariant: the two roots must have distinct hashes")

	require.Contains(t, stdout, "Record rec-a: VERIFIED (leaf hash and signature verified; merkle=OK, root="+rootHashA[:12]+"…)")
	require.Contains(t, stdout, "Record rec-b: VERIFIED (leaf hash and signature verified; merkle=OK, root="+rootHashB[:12]+"…)")

	require.NotContains(t, stdout, "Record rec-a: VERIFIED (leaf hash and signature verified; merkle=OK, root="+rootHashB[:12])
	require.NotContains(t, stdout, "Record rec-b: VERIFIED (leaf hash and signature verified; merkle=OK, root="+rootHashA[:12])
}

// TestRun_TrustedNowZeroIsHonored asserts that an explicit --trusted-now 0
// is used as-is (epoch-0) rather than silently replaced by time.Now(). The
// bundle's retention policy is "relative" with a 1-day window measured from
// a 2023 record timestamp: at trustedNowMs=0 the floor is deeply negative
// (no warning), but at the real current time the floor lands long after
// 2023 (warning). If --trusted-now 0 were being overridden with time.Now(),
// this run would incorrectly show the warning.
func TestRun_TrustedNowZeroIsHonored(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildRelativeRetentionBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath, "--trusted-now", "0"})
	require.Equal(t, 0, code)
	require.NotContains(t, stdout, "Retention floor: WARNING")

	code, stdout, _ = runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "Retention floor: WARNING")
}

// TestRun_TrustedNowNonNumericExitsThree is the regression for i-2kth: a
// non-numeric --trusted-now value must resolve to the documented exit-3
// "invalid flag value" path like every other flag, not framework-level flag
// parsing (which previously produced an unconditional exit 1 via
// urfave/cli's own strconv-based Int64Flag parsing failing before Run() ever
// ran -- indistinguishable by exit code from a genuine TAMPERED result).
func TestRun_TrustedNowNonNumericExitsThree(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildVerifiedBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, _, stderr := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath, "--trusted-now", "notanumber"})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "invalid --trusted-now value")
}

// TestRun_UnparseableRetentionPolicyExitsOneWithExplanation guards against
// the CLI silently exiting 1 with an otherwise-clean-looking report when
// FloorOK is nil (unparseable retention_policy) -- see
// pkg/audit/verify/retention.go's fail-closed contract on retentionFloorOK.
func TestRun_UnparseableRetentionPolicyExitsOneWithExplanation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM := buildUnparseableRetentionPolicyBundle(t)
	bundlePath := writeTempFile(t, dir, "bundle.json", bundleJSON)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 1, code)
	require.Contains(t, stdout, "VERIFIED")
	require.Contains(t, stdout, "Root signature: OK")
	require.Contains(t, stdout, "Retention floor: ERROR — could not parse retention_policy")
	// i-40fn: "Result set: complete" (SetStatus deliberately ignores
	// FloorOK==nil) can otherwise look self-contradictory next to exit 1 --
	// the trailing verdict line must resolve that unambiguously.
	require.Contains(t, stdout, "Result set: complete")
	require.Contains(t, stdout, "RESULT: FAILED (exit 1)")
}

// TestPrintResult_ImmudbAnchorSurfacesDetail is a direct-call unit test of
// printResult()'s immudb branch (unlike TestRun_ImmudbAnchorVerified, which
// exercises the same line via the full Run() path): Result.ImmudbResult.
// Detail (e.g. a set bundle's i-5fbz partial-coverage summary, "verified for
// 1 of 2 roots; 1 skipped") must always be surfaced in the VERIFIED line,
// not silently dropped.
func TestPrintResult_ImmudbAnchorSurfacesDetail(t *testing.T) {
	t.Parallel()

	result := auditverify.Result{
		SetStatus: auditverify.SetComplete,
		ChainOK:   auditverify.ChainOK,
		RootSigOK: true,
		ImmudbResult: &auditverify.ImmudbResult{
			Status: auditverify.AnchorVerified,
			Detail: "immudb anchor verified for 1 of 2 roots; 1 skipped",
		},
	}
	var buf bytes.Buffer
	printResult(&buf, result)
	require.Contains(t, buf.String(), "immudb anchor: VERIFIED — immudb anchor verified for 1 of 2 roots; 1 skipped")
}
