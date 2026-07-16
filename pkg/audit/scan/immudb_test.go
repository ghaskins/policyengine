//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"context"
	"crypto/sha256"
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

	"github.com/manetu/policyengine/pkg/audit/verify"
)

// TestComputeImmudbALHAgreesWithVerifyPackage cross-checks this package's
// self-contained ALH recomputation against pkg/audit/verify's
// ComputeImmudbALH -- two independent implementations agreeing byte-for-byte
// is a stronger correctness signal than either alone (mirroring s-3vlq
// decision 6's parity-oracle rationale for keeping pkg/audit/verify around).
func TestComputeImmudbALHAgreesWithVerifyPackage(t *testing.T) {
	eh := sha256.Sum256([]byte("eh"))
	prevAlh := sha256.Sum256([]byte("prev"))
	blRoot := sha256.Sum256([]byte("blroot"))

	local := immudbALHFields{
		TxID: 7, PrevALH: prevAlh[:], TS: 1700000000, Version: 1,
		Nentries: 1, EH: eh[:], BlTxID: 3, BlRoot: blRoot[:],
	}
	got := computeImmudbALH(local)

	want, err := verify.ComputeImmudbALH(verify.ImmudbALHFields{
		TxID: 7, PrevALH: prevAlh[:], TS: 1700000000, Version: 1,
		Nentries: 1, EH: eh[:], BlTxID: 3, BlRoot: blRoot[:],
	})
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestComputeImmudbALHAgreesWithVerifyPackageVersion0(t *testing.T) {
	eh := sha256.Sum256([]byte("eh-v0"))
	local := immudbALHFields{TxID: 1, PrevALH: zeroHash32, TS: 1, Version: 0, Nentries: 5, EH: eh[:], BlTxID: 0, BlRoot: zeroHash32}
	got := computeImmudbALH(local)

	want, err := verify.ComputeImmudbALH(verify.ImmudbALHFields{
		TxID: 1, PrevALH: zeroHash32, TS: 1, Version: 0, Nentries: 5, EH: eh[:], BlTxID: 0, BlRoot: zeroHash32,
	})
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestImmudbHTreeLeafMatchesInclusionCheckForSingleEntryTx(t *testing.T) {
	key := []byte("root-id-1")
	value := []byte(`{"root_hash_b64":"abc"}`)
	leaf := immudbHTreeLeaf(key, value)
	// For a single-entry tx (nentries=1), entry_hash IS tx_eH -- confirm
	// pkg/audit/verify.VerifyImmudbInclusion agrees with an empty proof.
	assert.True(t, verify.VerifyImmudbInclusion(leaf, nil, 1, leaf))
	assert.False(t, verify.VerifyImmudbInclusion(leaf, nil, 2, leaf), "an empty proof must fail closed for nentries > 1")
}

func TestParseTxHeaderRejectsNonEmptyMetadata(t *testing.T) {
	h := immudbTxHeader{EH: "AAAA", Metadata: []byte(`{"foo":"bar"}`)}
	_, err := parseTxHeader(h)
	assert.Error(t, err, "a header with non-empty metadata is not ALH-recomputable from its JSON projection and must fail closed")
}

func TestParseTxHeaderRequiresEH(t *testing.T) {
	h := immudbTxHeader{}
	_, err := parseTxHeader(h)
	assert.Error(t, err)
}

func TestLatestPtrKeyMatchesClojureConvention(t *testing.T) {
	assert.Equal(t, "partition-3-latest", latestPtrKey(3))
}

// fakeImmudbSQLServer is a minimal httptest.Server implementing just enough
// of immudb's REST gateway (/api/login, /api/db/sqlquery) to drive
// queryRootsIndexPage/rootsInWindow's pagination and cap logic (s-8snm
// decision 3) directly against real HTTP round-trips, without the full
// verifiable/get cryptographic machinery EnumerateRootsInWindow also needs
// (that end-to-end path is exercised via fakeAnchorClient at the scan level
// instead; a real-immudb integration test remains deferred, see i-1ahd).
// It reads rootsWindowPageSize/immudbMaxWindowRoots directly rather than
// parsing "LIMIT n" out of the request SQL text, since both live in the same
// test process.
func newFakeImmudbSQLServer(t *testing.T, rows []windowRow) *httptest.Server {
	t.Helper()
	sorted := make([]windowRow, len(rows))
	copy(sorted, rows)
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
	return httptest.NewServer(mux)
}

func TestImmudbRootsInWindowPaginatesWithoutSkipOrDuplicateOnTie(t *testing.T) {
	origPageSize := rootsWindowPageSize
	rootsWindowPageSize = 2
	defer func() { rootsWindowPageSize = origPageSize }()

	// Two rows share notary_ts_to=100 -- the composite (notary_ts_to,
	// root_id) keyset cursor must not skip or duplicate either one across
	// the page boundary this tie sits on.
	rows := []windowRow{
		{notaryTsTo: 100, rootID: "root-a"},
		{notaryTsTo: 100, rootID: "root-b"},
		{notaryTsTo: 200, rootID: "root-c"},
		{notaryTsTo: 300, rootID: "root-d"},
		{notaryTsTo: 300, rootID: "root-e"},
	}
	srv := newFakeImmudbSQLServer(t, rows)
	defer srv.Close()

	client := &ImmudbClient{BaseURL: srv.URL}
	got, err := client.rootsInWindow(context.Background(), 0, 0, 1000)
	require.NoError(t, err)
	assert.Equal(t, []string{"root-a", "root-b", "root-c", "root-d", "root-e"}, got)
}

func TestImmudbRootsInWindowExceedsCapReturnsError(t *testing.T) {
	origCap := immudbMaxWindowRoots
	immudbMaxWindowRoots = 2
	defer func() { immudbMaxWindowRoots = origCap }()

	rows := []windowRow{
		{notaryTsTo: 100, rootID: "root-a"},
		{notaryTsTo: 200, rootID: "root-b"},
		{notaryTsTo: 300, rootID: "root-c"},
	}
	srv := newFakeImmudbSQLServer(t, rows)
	defer srv.Close()

	client := &ImmudbClient{BaseURL: srv.URL}
	_, err := client.rootsInWindow(context.Background(), 0, 0, 1000)
	require.Error(t, err, "an oversized window must throw, never silently truncate (s-8snm decision 3)")
	assert.Contains(t, err.Error(), "exceeds immudbMaxWindowRoots")
}

// newFakeImmudbKVServer is a minimal httptest.Server implementing just
// enough of immudb's REST gateway (/api/login, /api/db/verifiable/get) to
// drive AnchorHead's notary-ts-to round-trip (s-8snm decision 2) over a real
// HTTP call, without the full ALH/inclusion-proof verification machinery
// AnchorHead itself never touches (it only reads entry.value).
func newFakeImmudbKVServer(t *testing.T, kv map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"token":"tok"}`)
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

func TestImmudbAnchorHeadNotaryTsToRoundTrip(t *testing.T) {
	srv := newFakeImmudbKVServer(t, map[string]string{
		"partition-0-latest": `{"root-id":"root-z","to-seq":42,"notary-ts-to":99999}`,
	})
	defer srv.Close()

	client := &ImmudbClient{BaseURL: srv.URL}
	head, err := client.AnchorHead(context.Background(), 0)
	require.NoError(t, err)
	require.NotNil(t, head)
	assert.Equal(t, "root-z", head.RootID)
	assert.Equal(t, int64(42), head.ToSeq)
	assert.Equal(t, int64(99999), head.NotaryTsTo)
}

func TestImmudbAnchorHeadNotaryTsToAbsentDefaultsZero(t *testing.T) {
	// A pointer written before s-8snm decision 2 has no notary-ts-to key at
	// all -- must decode to 0, not error (a zero value only ever makes scan
	// step 5's tail check MORE cautious, never less).
	srv := newFakeImmudbKVServer(t, map[string]string{
		"partition-0-latest": `{"root-id":"root-old","to-seq":7}`,
	})
	defer srv.Close()

	client := &ImmudbClient{BaseURL: srv.URL}
	head, err := client.AnchorHead(context.Background(), 0)
	require.NoError(t, err)
	require.NotNil(t, head)
	assert.Equal(t, int64(0), head.NotaryTsTo)
}

func TestImmudbAnchorHeadNilWhenNeverAnchored(t *testing.T) {
	srv := newFakeImmudbKVServer(t, map[string]string{})
	defer srv.Close()

	client := &ImmudbClient{BaseURL: srv.URL}
	head, err := client.AnchorHead(context.Background(), 5)
	require.NoError(t, err)
	assert.Nil(t, head)
}
