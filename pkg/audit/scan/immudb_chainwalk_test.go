//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFakeImmudbChainWalkServer combines newFakeImmudbSQLServer's discovery-
// index handling and newFakeImmudbKVServer's verifiable/get handling into one
// server, so a single real ImmudbClient can exercise EnumerateRootsInWindow's
// full path -- SQL-derived enumeration plus the recoverChainGaps fallback --
// against a discovery index (indexRows) that may deliberately omit a row
// still present in the verified KV store (kv), or omit it from both.
func newFakeImmudbChainWalkServer(t *testing.T, kv map[string]string, indexRows []windowRow) *httptest.Server {
	t.Helper()
	sorted := make([]windowRow, len(indexRows))
	copy(sorted, indexRows)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].notaryTsTo != sorted[j].notaryTsTo {
			return sorted[i].notaryTsTo < sorted[j].notaryTsTo
		}
		return sorted[i].rootID < sorted[j].rootID
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"token":"tok"}`)
	})
	mux.HandleFunc("/api/db/sqlquery", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Params []struct {
				Name  string                 `json:"name"`
				Value map[string]interface{} `json:"value"`
			} `json:"params"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))

		params := map[string]string{}
		for _, p := range body.Params {
			if s, ok := p.Value["s"].(string); ok {
				params[p.Name] = s
			}
			if n, ok := p.Value["n"].(string); ok {
				params[p.Name] = n
			}
		}
		fromTS, _ := strconv.ParseInt(params["from_ts"], 10, 64)
		toTS, _ := strconv.ParseInt(params["to_ts"], 10, 64)
		afterTS, hasAfter := int64(0), false
		if v, ok := params["after_ts"]; ok {
			hasAfter = true
			afterTS, _ = strconv.ParseInt(v, 10, 64)
		}
		afterRoot := params["after_root_id"]

		var matched []windowRow
		for _, row := range sorted {
			if row.notaryTsTo < fromTS || row.notaryTsTo >= toTS {
				continue
			}
			if hasAfter && row.notaryTsTo <= afterTS && (row.notaryTsTo != afterTS || row.rootID <= afterRoot) {
				continue
			}
			matched = append(matched, row)
		}
		if len(matched) > rootsWindowPageSize {
			matched = matched[:rootsWindowPageSize]
		}

		type sqlRow struct {
			Values []sqlValue `json:"values"`
		}
		resp := struct {
			Rows []sqlRow `json:"rows"`
		}{}
		for _, row := range matched {
			ts := strconv.FormatInt(row.notaryTsTo, 10)
			rootID := row.rootID
			resp.Rows = append(resp.Rows, sqlRow{Values: []sqlValue{{N: &ts}, {S: &rootID}}})
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	})
	mux.HandleFunc("/api/db/verifiable/get", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			KeyRequest struct {
				Key string `json:"key"`
			} `json:"keyRequest"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		keyBytes, err := base64.StdEncoding.DecodeString(body.KeyRequest.Key)
		require.NoError(t, err)
		value, ok := kv[string(keyBytes)]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"error":"key not found"}`)
			return
		}
		resp := map[string]interface{}{
			"entry": map[string]interface{}{
				"value": base64.StdEncoding.EncodeToString([]byte(value)),
			},
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	})
	return httptest.NewServer(mux)
}

// rootJSON marshals a signed-root payload map (e.g. from buildSignedRoot) the
// same way the notary write path stores it as an immudb KV value.
func rootJSON(t *testing.T, root map[string]interface{}) string {
	t.Helper()
	b, err := json.Marshal(root)
	require.NoError(t, err)
	return string(b)
}

func rootID(t *testing.T, root map[string]interface{}) string {
	t.Helper()
	id, ok := getString(root, "root_hash_b64")
	require.True(t, ok)
	return "root-" + id
}

func latestPtrJSON(t *testing.T, rid string, toSeq, notaryTsTo int64) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"root-id":      rid,
		"to-seq":       toSeq,
		"notary-ts-to": notaryTsTo,
	})
	require.NoError(t, err)
	return string(b)
}

// TestImmudbEnumerateRootsInWindowRecoversInternalIndexGap is regression (a)
// from s-5910: a notary_root_index row for an otherwise durably-anchored
// root (B, in the middle of the chain) goes missing while B's own verified
// KV entry is untouched. EnumerateRootsInWindow must recover B via the
// prev_root_id chain-walk fallback and return the full, correctly-ordered
// A->B->C chain -- exactly what scan.go's step-2b chain check needs to avoid
// raising a false "chain" finding for a gap that was never real tampering.
func TestImmudbEnumerateRootsInWindowRecoversInternalIndexGap(t *testing.T) {
	kp := genTestKeyPair(t)
	rootA := buildSignedRoot(t, kp, "hash-a", 0, 1, 1, 0, 0, 100, nil, nil)
	idA := rootID(t, rootA)
	rootB := buildSignedRoot(t, kp, "hash-b", 0, 1, 1, 1, 1, 200, idA, "hash-a")
	idB := rootID(t, rootB)
	rootC := buildSignedRoot(t, kp, "hash-c", 0, 1, 1, 2, 2, 300, idB, "hash-b")
	idC := rootID(t, rootC)

	kv := map[string]string{
		idA: rootJSON(t, rootA),
		idB: rootJSON(t, rootB),
		idC: rootJSON(t, rootC),
	}
	// B's discovery-index row is silently missing -- only A and C are named.
	indexRows := []windowRow{
		{notaryTsTo: 100, rootID: idA},
		{notaryTsTo: 300, rootID: idC},
	}
	srv := newFakeImmudbChainWalkServer(t, kv, indexRows)
	defer srv.Close()

	client := &ImmudbClient{BaseURL: srv.URL}
	got, err := client.EnumerateRootsInWindow(context.Background(), 0, 0, 1000)
	require.NoError(t, err)

	require.Len(t, got, 3)
	assert.Equal(t, []string{idA, idB, idC}, []string{got[0].RootID, got[1].RootID, got[2].RootID})
	// The recovered root's own linkage is intact -- exactly the condition
	// scan.go step 2b's chain check requires to report no finding.
	curPrevID, _ := getString(got[1].Payload, "prev_root_id")
	assert.Equal(t, idA, curPrevID)
	curPrevID, _ = getString(got[2].Payload, "prev_root_id")
	assert.Equal(t, idB, curPrevID)
}

// TestImmudbEnumerateRootsInWindowTailGapRecoveredViaAnchorHead exercises the
// AnchorHead-anchored trigger specifically (as opposed to the internal
// pairwise trigger above): the *last* root's own discovery-index row is
// missing, so only comparing the SQL-derived tail against AnchorHead can
// notice the gap -- realizing the original (now-corrected) comment's literal
// claim of "walking backward from AnchorHead."
func TestImmudbEnumerateRootsInWindowTailGapRecoveredViaAnchorHead(t *testing.T) {
	kp := genTestKeyPair(t)
	rootA := buildSignedRoot(t, kp, "hash-a", 0, 1, 1, 0, 0, 100, nil, nil)
	idA := rootID(t, rootA)
	rootB := buildSignedRoot(t, kp, "hash-b", 0, 1, 1, 1, 1, 200, idA, "hash-a")
	idB := rootID(t, rootB)

	kv := map[string]string{
		idA:             rootJSON(t, rootA),
		idB:             rootJSON(t, rootB),
		latestPtrKey(0): latestPtrJSON(t, idB, 1, 200),
	}
	// B (the tail/head) is missing from the discovery index entirely.
	indexRows := []windowRow{
		{notaryTsTo: 100, rootID: idA},
	}
	srv := newFakeImmudbChainWalkServer(t, kv, indexRows)
	defer srv.Close()

	client := &ImmudbClient{BaseURL: srv.URL}
	got, err := client.EnumerateRootsInWindow(context.Background(), 0, 0, 1000)
	require.NoError(t, err)

	require.Len(t, got, 2)
	assert.Equal(t, []string{idA, idB}, []string{got[0].RootID, got[1].RootID})
}

// TestImmudbEnumerateRootsInWindowGenuineAbsenceIsHardError is regression (b)
// from s-5910: both B's discovery-index row AND its verified KV entry are
// gone (as opposed to (a), where only the index row went missing). The
// chain-walk fallback must not treat this as "recovered, move on" -- A and C
// still name B as their link, so the walk reaches B's root-id and gets a
// genuine not-found from the verified store, which must still surface as a
// hard error (the same class of failure the scanner produces today for any
// other corrupted/inconsistent enumeration), never a silent pass.
func TestImmudbEnumerateRootsInWindowGenuineAbsenceIsHardError(t *testing.T) {
	kp := genTestKeyPair(t)
	rootA := buildSignedRoot(t, kp, "hash-a", 0, 1, 1, 0, 0, 100, nil, nil)
	idA := rootID(t, rootA)
	rootB := buildSignedRoot(t, kp, "hash-b", 0, 1, 1, 1, 1, 200, idA, "hash-a")
	idB := rootID(t, rootB)
	rootC := buildSignedRoot(t, kp, "hash-c", 0, 1, 1, 2, 2, 300, idB, "hash-b")
	idC := rootID(t, rootC)

	kv := map[string]string{
		idA: rootJSON(t, rootA),
		// idB deliberately absent from the verified KV store too.
		idC: rootJSON(t, rootC),
	}
	indexRows := []windowRow{
		{notaryTsTo: 100, rootID: idA},
		{notaryTsTo: 300, rootID: idC},
	}
	srv := newFakeImmudbChainWalkServer(t, kv, indexRows)
	defer srv.Close()

	client := &ImmudbClient{BaseURL: srv.URL}
	_, err := client.EnumerateRootsInWindow(context.Background(), 0, 0, 1000)
	require.Error(t, err, "genuine absence of a chain predecessor must fail closed, not be silently recovered as if it were only an index gap")
	assert.Contains(t, err.Error(), "does not exist in the anchor's verified store")
	assert.Contains(t, err.Error(), idB)
}

// TestImmudbEnumerateRootsInWindowFirstRootBoundaryIsNotAnError confirms the
// leading-gap check's cheap boundary case still behaves like scan.go's own
// documented caveat (scan.go:116-120): the first enumerated root's own
// prev_root_id may legitimately point outside the window (its predecessor's
// notary_ts_to < fromTS) -- that must never be misread as a recoverable gap
// or, worse, a hard error.
func TestImmudbEnumerateRootsInWindowFirstRootBoundaryIsNotAnError(t *testing.T) {
	kp := genTestKeyPair(t)
	rootA := buildSignedRoot(t, kp, "hash-a", 0, 1, 1, 0, 0, 50, nil, nil)
	idA := rootID(t, rootA)
	// rootB's predecessor is A, but A's notary_ts_to (50) sits below this
	// scan's fromTS (100) -- a genuinely out-of-window predecessor, not a
	// dropped index row.
	rootB := buildSignedRoot(t, kp, "hash-b", 0, 1, 1, 1, 1, 200, idA, "hash-a")
	idB := rootID(t, rootB)

	kv := map[string]string{
		idA: rootJSON(t, rootA),
		idB: rootJSON(t, rootB),
	}
	indexRows := []windowRow{
		{notaryTsTo: 200, rootID: idB},
	}
	srv := newFakeImmudbChainWalkServer(t, kv, indexRows)
	defer srv.Close()

	client := &ImmudbClient{BaseURL: srv.URL}
	got, err := client.EnumerateRootsInWindow(context.Background(), 0, 100, 1000)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, idB, got[0].RootID)
}

// TestImmudbEnumerateRootsInWindowChainWalkBoundedThrows mirrors
// TestImmudbRootsInWindowExceedsCapReturnsError's throw-never-silently-
// truncate convention for the chain-walk fallback specifically: a gap deeper
// than immudbMaxChainWalkSteps must throw, never silently give up partway
// and return an incomplete-but-unflagged result.
func TestImmudbEnumerateRootsInWindowChainWalkBoundedThrows(t *testing.T) {
	origCap := immudbMaxChainWalkSteps
	immudbMaxChainWalkSteps = 1
	defer func() { immudbMaxChainWalkSteps = origCap }()

	kp := genTestKeyPair(t)
	rootA := buildSignedRoot(t, kp, "hash-a", 0, 1, 1, 0, 0, 100, nil, nil)
	idA := rootID(t, rootA)
	rootB := buildSignedRoot(t, kp, "hash-b", 0, 1, 1, 1, 1, 200, idA, "hash-a")
	idB := rootID(t, rootB)
	rootC := buildSignedRoot(t, kp, "hash-c", 0, 1, 1, 2, 2, 300, idB, "hash-b")
	idC := rootID(t, rootC)

	kv := map[string]string{
		idA: rootJSON(t, rootA),
		idB: rootJSON(t, rootB),
		idC: rootJSON(t, rootC),
	}
	// Both A and B's discovery-index rows are missing -- a 2-hop gap, deeper
	// than the (lowered) 1-step cap.
	indexRows := []windowRow{
		{notaryTsTo: 300, rootID: idC},
	}
	srv := newFakeImmudbChainWalkServer(t, kv, indexRows)
	defer srv.Close()

	client := &ImmudbClient{BaseURL: srv.URL}
	_, err := client.EnumerateRootsInWindow(context.Background(), 0, 0, 1000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeded immudbMaxChainWalkSteps")
}
