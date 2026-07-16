//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/manetu/policyengine/pkg/audit/verify"
)

type testKeyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func genTestKeyPair(t *testing.T) testKeyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return testKeyPair{pub: pub, priv: priv}
}

// normalizeMap round-trips v through JSON encode/decodeJSONMap, so tests
// build fixtures the same way a real fetch would decode one -- integers
// become json.Number, matching every accessor helper's expectation.
func normalizeMap(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	m, err := decodeJSONMap(data)
	require.NoError(t, err)
	return m
}

// signRoot computes the canonical-JSON signature over root's
// verify.SignableRootFields subset (the 10-field allowlist) and injects
// root_signature_b64/root_key_id -- root must already be a normalized map.
func signRoot(t *testing.T, kp testKeyPair, root map[string]interface{}) {
	t.Helper()
	signable := selectSignableFields(root)
	payload, err := verify.CanonicalJSONBytes(signable)
	require.NoError(t, err)
	sig := ed25519.Sign(kp.priv, payload)
	root["root_signature_b64"] = base64.RawURLEncoding.EncodeToString(sig)
	root["root_key_id"] = "test-key"
}

// buildSignedRoot builds and signs a normalized signed-root payload covering
// exactly one batch (or a heartbeat, when treeSize == 0), for a single
// partition. notaryTs is used for both notary_ts_from/notary_ts_to (every
// root this codebase writes seals atomically -- see batcher.clj).
func buildSignedRoot(t *testing.T, kp testKeyPair, rootHashB64 string, partition, partitionCount, treeSize int, fromSeq, toSeq, notaryTs int64, prevRootID, prevRootHashB64 interface{}) map[string]interface{} {
	t.Helper()
	root := normalizeMap(t, map[string]interface{}{
		"root_hash_b64":      rootHashB64,
		"tree_size":          treeSize,
		"partition":          partition,
		"partition_count":    partitionCount,
		"covered_range":      map[string]interface{}{"from_seq": fromSeq, "to_seq": toSeq},
		"prev_root_hash_b64": prevRootHashB64,
		"prev_root_id":       prevRootID,
		"notary_ts_from":     notaryTs,
		"notary_ts_to":       notaryTs,
		"retention_policy":   map[string]interface{}{"mode": "retain-all"},
	})
	signRoot(t, kp, root)
	return root
}

// buildBatch builds tree_size leaves for one batch (content hashes derived
// deterministically from an index), the positioned Merkle tree over them,
// and a signed root covering them -- everything a step-7 density recompute
// needs to agree with.
type testBatch struct {
	root        map[string]interface{}
	leaves      []LeafRow
	contentHash map[int64][]byte // leaf_index -> raw content hash (SHA-256(record_pb))
}

func buildBatch(t *testing.T, kp testKeyPair, partition, partitionCount int, fromSeq int64, n int, notaryTs int64, prevRootID, prevRootHashB64 interface{}) testBatch {
	t.Helper()
	leafHashes := make([][]byte, n)
	contentHashes := make(map[int64][]byte, n)
	leaves := make([]LeafRow, n)
	for i := 0; i < n; i++ {
		content := sha256.Sum256([]byte{byte(i), byte(fromSeq), byte(partition)})
		contentHashes[int64(i)] = content[:]
		lh, err := verify.PositionedLeafHash(int64(partition), fromSeq+int64(i), int64(i), notaryTs, b64urlEncode(content[:]))
		require.NoError(t, err)
		leafHashes[i] = lh
		leaves[i] = LeafRow{ID: idFor(partition, fromSeq+int64(i)), Seq: fromSeq + int64(i), LeafIndex: int64(i), LeafHashB64: b64urlEncode(content[:])}
	}
	tree := verify.BuildTree(leafHashes)
	rootBytes, err := verify.Root(tree)
	require.NoError(t, err)
	root := buildSignedRoot(t, kp, b64urlEncode(rootBytes), partition, partitionCount, n, fromSeq, fromSeq+int64(n)-1, notaryTs, prevRootID, prevRootHashB64)
	return testBatch{root: root, leaves: leaves, contentHash: contentHashes}
}

func idFor(partition int, seq int64) string {
	return "rec-" + b64urlEncode([]byte{byte(partition)}) + "-" + b64urlEncode([]byte{byte(seq)})
}
