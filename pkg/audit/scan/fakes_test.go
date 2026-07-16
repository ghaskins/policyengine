//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeAnchorClient is an in-memory AnchorClient, so scan-algorithm tests
// don't need a real S3/immudb backend.
type fakeAnchorClient struct {
	tier    string
	heads   map[int]*AnchorPointer
	windows map[int][]EnumeratedRoot // partition -> every root ever anchored, ascending by notary_ts_to
	// proofOverride, keyed by root-id, lets a test force VerifyAnchorProof to
	// fail for a specific root; absent means OK.
	proofOverride map[string]AnchorProofResult
	enumerateErr  map[int]error
}

func newFakeAnchorClient() *fakeAnchorClient {
	return &fakeAnchorClient{
		tier:          "fake:test-tier",
		heads:         map[int]*AnchorPointer{},
		windows:       map[int][]EnumeratedRoot{},
		proofOverride: map[string]AnchorProofResult{},
		enumerateErr:  map[int]error{},
	}
}

func (f *fakeAnchorClient) Tier() string { return f.tier }

func (f *fakeAnchorClient) AnchorHead(_ context.Context, partition int) (*AnchorPointer, error) {
	return f.heads[partition], nil
}

func (f *fakeAnchorClient) EnumerateRootsInWindow(_ context.Context, partition int, fromTS, toTS int64) ([]EnumeratedRoot, error) {
	if err := f.enumerateErr[partition]; err != nil {
		return nil, err
	}
	var out []EnumeratedRoot
	for _, r := range f.windows[partition] {
		ts, _ := getInt64(r.Payload, "notary_ts_to")
		if ts >= fromTS && ts < toTS {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeAnchorClient) VerifyAnchorProof(_ context.Context, root EnumeratedRoot, _ interface{}) (AnchorProofResult, error) {
	if r, ok := f.proofOverride[root.RootID]; ok {
		return r, nil
	}
	return AnchorProofResult{OK: true, Detail: "fake: verified"}, nil
}

func (f *fakeAnchorClient) AnchorRef(_ context.Context, root EnumeratedRoot) (map[string]interface{}, error) {
	return map[string]interface{}{"builtin": map[string]interface{}{"root_id": root.RootID}}, nil
}

// fakeNotaryServer is an httptest.Server implementing the two NDJSON
// endpoints (GET /api/v1/notary/leaves, POST /api/v1/notary/record-existence),
// driven by test-controlled in-memory data.
type fakeNotaryServer struct {
	*httptest.Server
	leaves    map[string][]LeafRow // root-id -> leaves
	existence map[string]RecordExistenceRow
}

func newFakeNotaryServer(t *testing.T) *fakeNotaryServer {
	t.Helper()
	fs := &fakeNotaryServer{leaves: map[string][]LeafRow{}, existence: map[string]RecordExistenceRow{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/notary/leaves", func(w http.ResponseWriter, r *http.Request) {
		rootID := r.URL.Query().Get("root_id")
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, l := range fs.leaves[rootID] {
			row := map[string]interface{}{"id": l.ID, "seq": l.Seq, "leaf_index": l.LeafIndex, "leaf_hash_b64": l.LeafHashB64}
			b, _ := json.Marshal(row)
			_, _ = fmt.Fprintf(w, "%s\n", b)
		}
	})
	mux.HandleFunc("/api/v1/notary/record-existence", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IDs []string `json:"ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, id := range body.IDs {
			row, ok := fs.existence[id]
			if !ok {
				row = RecordExistenceRow{ID: id, Found: true, LeafHashB64: "unused", SignatureB64: "unused"}
			}
			var out map[string]interface{}
			if row.Found {
				out = map[string]interface{}{"id": row.ID, "found": true, "leaf_hash_b64": row.LeafHashB64, "signature_b64": row.SignatureB64}
			} else {
				var aa interface{}
				if row.AuthorizedAbsent != nil {
					aa = *row.AuthorizedAbsent
				}
				out = map[string]interface{}{"id": row.ID, "found": false, "authorized_absent": aa}
			}
			b, _ := json.Marshal(out)
			_, _ = fmt.Fprintf(w, "%s\n", b)
		}
	})
	fs.Server = httptest.NewServer(mux)
	t.Cleanup(fs.Close)
	return fs
}

func (fs *fakeNotaryServer) client() *NotaryClient {
	return &NotaryClient{BaseURL: fs.URL, HTTPClient: fs.Client()}
}
