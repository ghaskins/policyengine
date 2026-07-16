//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// NotaryClient is an HTTP client for iam-lite's read-only NDJSON completeness
// endpoints (s-3vlq decision 5): GET /api/v1/notary/leaves and POST
// /api/v1/notary/record-existence. Every field either endpoint returns is
// self-authenticating (hash- or signature-checked downstream by the scan
// algorithm), so routing through the service costs no trust -- a compromised
// service can only omit rows, which the scan's density/existence checks
// already catch.
type NotaryClient struct {
	BaseURL    string // e.g. "https://iam-lite.internal"
	HTTPClient *http.Client
	// AuthHeader, when non-empty, is set verbatim on every request (e.g.
	// "Bearer <token>" or "Basic <creds>") -- the same OIDC/basic-auth guard
	// every other iam-lite route requires.
	AuthHeader string
}

func (c *NotaryClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *NotaryClient) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	var r *http.Request
	var err error
	if body != nil {
		r, err = http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	} else {
		r, err = http.NewRequestWithContext(ctx, method, c.BaseURL+path, nil)
	}
	if err != nil {
		return nil, err
	}
	if c.AuthHeader != "" {
		r.Header.Set("Authorization", c.AuthHeader)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return r, nil
}

// readNDJSON streams resp's body line by line, decoding each into a fresh
// map[string]interface{} (json.Number for numerics), and calls onRow for
// each. Never buffers the whole response in memory.
func readNDJSON(body *http.Response, onRow func(map[string]interface{}) error) error {
	defer func() { _ = body.Body.Close() }()
	scanner := bufio.NewScanner(body.Body)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		row, err := decodeJSONMap(line)
		if err != nil {
			return fmt.Errorf("notary-client: malformed NDJSON row: %w", err)
		}
		if err := onRow(row); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// Leaves fetches the ordered leaf set sealed under rootID, via
// GET /api/v1/notary/leaves?root_id=<id> -- scan step 7's input.
func (c *NotaryClient) Leaves(ctx context.Context, rootID string) ([]LeafRow, error) {
	path := "/api/v1/notary/leaves?root_id=" + url.QueryEscape(rootID)
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("notary-client: leaves request failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		return nil, fmt.Errorf("notary-client: leaves request for root %q failed: status %d", rootID, resp.StatusCode)
	}
	var out []LeafRow
	err = readNDJSON(resp, func(row map[string]interface{}) error {
		id, _ := getString(row, "id")
		seq, _ := getInt64(row, "seq")
		leafIndex, _ := getInt64(row, "leaf_index")
		leafHashB64, _ := getString(row, "leaf_hash_b64")
		out = append(out, LeafRow{ID: id, Seq: seq, LeafIndex: leafIndex, LeafHashB64: leafHashB64})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RecordExistence checks per-id presence in accesslog, retention-floor-aware,
// via POST /api/v1/notary/record-existence -- scan step 8's input. iam-lite
// caps a single request at leaf-index/max-batch-size ids; callers with more
// ids must chunk.
func (c *NotaryClient) RecordExistence(ctx context.Context, ids []string) ([]RecordExistenceRow, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	body, err := json.Marshal(map[string]interface{}{"ids": ids})
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, http.MethodPost, "/api/v1/notary/record-existence", body)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("notary-client: record-existence request failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		return nil, fmt.Errorf("notary-client: record-existence request failed: status %d", resp.StatusCode)
	}
	var out []RecordExistenceRow
	err = readNDJSON(resp, func(row map[string]interface{}) error {
		id, _ := getString(row, "id")
		found, _ := row["found"].(bool)
		r := RecordExistenceRow{ID: id, Found: found}
		if found {
			r.LeafHashB64, _ = getString(row, "leaf_hash_b64")
			r.SignatureB64, _ = getString(row, "signature_b64")
		} else if v, ok := row["authorized_absent"]; ok && v != nil {
			if b, ok := v.(bool); ok {
				r.AuthorizedAbsent = &b
			}
		}
		out = append(out, r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
