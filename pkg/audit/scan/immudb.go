//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/manetu/policyengine/pkg/audit/verify"
)

// ImmudbClient is a direct client for immudb's embedded REST gateway,
// mirroring mpe-iam-lite's notary/anchor/immudb.clj wire protocol exactly:
// login (POST /api/login, base64-encoded credentials), an optional
// per-database token re-scope (GET /api/db/use/<db>), verifiable KV reads
// (POST /api/db/verifiable/get), and the untrusted SQL discovery index
// (POST /api/db/sqlquery). All paths are mounted under /api with NO
// api/v1 prefix and NO <database> path segment (the session token is
// already db-scoped).
type ImmudbClient struct {
	BaseURL    string // e.g. "https://immudb.internal:8080"
	Database   string
	Username   string
	Password   string
	HTTPClient *http.Client

	mu    sync.Mutex
	token string
}

const rootsIndexTable = "notary_root_index"

// proofFailure wraps a content-level anchor-proof problem (root not found,
// malformed stored value, a header that is not ALH-recomputable) -- as
// opposed to a transport/infrastructure error reaching the anchor at all.
// VerifyAnchorProof unwraps this into a graceful AnchorProofResult{OK:
// false}; any other error aborts the scan, since a network blip must never
// silently manufacture a false tamper finding.
type proofFailure struct{ detail string }

func (e *proofFailure) Error() string { return e.detail }

func newProofFailure(format string, args ...interface{}) error {
	return &proofFailure{detail: fmt.Sprintf(format, args...)}
}

func (c *ImmudbClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *ImmudbClient) Tier() string { return "immudb:cryptographic-tamper-evidence" }

// --- session management ---

func (c *ImmudbClient) doLogin(ctx context.Context) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"user":     base64.StdEncoding.EncodeToString([]byte(c.Username)),
		"password": base64.StdEncoding.EncodeToString([]byte(c.Password)),
	})
	resp, err := c.post(ctx, "", c.BaseURL+"/api/login", body)
	if err != nil {
		return "", fmt.Errorf("immudb: login request failed: %w", err)
	}
	if resp.status != 200 {
		return "", fmt.Errorf("immudb: login failed: status %d", resp.status)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp.body, &out); err != nil {
		return "", fmt.Errorf("immudb: login response decode failed: %w", err)
	}
	token := out.Token
	if c.Database != "" && c.Database != "defaultdb" {
		useResp, err := c.getWithAuth(ctx, c.BaseURL+"/api/db/use/"+c.Database, token)
		if err != nil {
			return "", fmt.Errorf("immudb: use-database request failed: %w", err)
		}
		if useResp.status != 200 {
			return "", fmt.Errorf("immudb: use-database failed: status %d", useResp.status)
		}
		var useOut struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(useResp.body, &useOut); err != nil {
			return "", fmt.Errorf("immudb: use-database response decode failed: %w", err)
		}
		token = useOut.Token
	}
	return token, nil
}

func (c *ImmudbClient) currentToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return c.token, nil
	}
	tok, err := c.doLogin(ctx)
	if err != nil {
		return "", err
	}
	c.token = tok
	return tok, nil
}

func (c *ImmudbClient) resetToken() {
	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()
}

type httpResult struct {
	status int
	body   []byte
}

func (c *ImmudbClient) post(ctx context.Context, token, url string, body []byte) (httpResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return httpResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return httpResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return httpResult{}, err
	}
	return httpResult{status: resp.StatusCode, body: b}, nil
}

func (c *ImmudbClient) getWithAuth(ctx context.Context, url, token string) (httpResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return httpResult{}, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return httpResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return httpResult{}, err
	}
	return httpResult{status: resp.StatusCode, body: b}, nil
}

// callWithRefresh mirrors immudb.clj's call-with-refresh: use the cached
// token, and on a 401 re-login once and retry.
func (c *ImmudbClient) callWithRefresh(ctx context.Context, url string, body []byte) (httpResult, error) {
	tok, err := c.currentToken(ctx)
	if err != nil {
		return httpResult{}, err
	}
	resp, err := c.post(ctx, tok, url, body)
	if err != nil {
		return httpResult{}, err
	}
	if resp.status == 401 {
		c.resetToken()
		tok, err = c.currentToken(ctx)
		if err != nil {
			return httpResult{}, err
		}
		return c.post(ctx, tok, url, body)
	}
	return resp, nil
}

// keyNotFound mirrors immudb.clj's key-not-found?: real immudb does not 404
// on a missing key from verifiable/get -- it surfaces as a non-200 status
// with a "key not found" message.
func keyNotFound(resp httpResult) bool {
	if resp.status == 404 {
		return true
	}
	if resp.status == 200 {
		return false
	}
	return bytes.Contains(bytes.ToLower(resp.body), []byte("key not found"))
}

// --- verifiable/get ---

type immudbTxHeader struct {
	ID       json.Number     `json:"id"`
	PrevAlh  string          `json:"prevAlh"`
	TS       json.Number     `json:"ts"`
	Version  json.Number     `json:"version"`
	Nentries json.Number     `json:"nentries"`
	EH       string          `json:"eH"`
	BlTxID   json.Number     `json:"blTxId"`
	BlRoot   string          `json:"blRoot"`
	Metadata json.RawMessage `json:"metadata"`
}

func headerLong(n json.Number) int64 {
	if n == "" {
		return 0
	}
	v, _ := n.Int64()
	return v
}

type verifiableGetResponse struct {
	Entry struct {
		Value string      `json:"value"`
		Tx    json.Number `json:"tx"`
	} `json:"entry"`
	VerifiableTx struct {
		Tx struct {
			Header immudbTxHeader `json:"header"`
		} `json:"tx"`
		Signature struct {
			PublicKey string `json:"publicKey"`
			Signature string `json:"signature"`
		} `json:"signature"`
	} `json:"verifiableTx"`
	InclusionProof struct {
		Terms []string `json:"terms"`
	} `json:"inclusionProof"`
}

func (c *ImmudbClient) verifiableGet(ctx context.Context, key string) (*verifiableGetResponse, error) {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"keyRequest":   map[string]string{"key": base64.StdEncoding.EncodeToString([]byte(key))},
		"proveSinceTx": "0",
	})
	resp, err := c.callWithRefresh(ctx, c.BaseURL+"/api/db/verifiable/get", reqBody)
	if err != nil {
		return nil, err
	}
	if keyNotFound(resp) {
		return nil, nil
	}
	if resp.status != 200 {
		return nil, fmt.Errorf("immudb: verifiable/get failed for key %q: status %d: %s", key, resp.status, string(resp.body))
	}
	var out verifiableGetResponse
	if err := json.Unmarshal(resp.body, &out); err != nil {
		return nil, fmt.Errorf("immudb: verifiable/get response decode failed: %w", err)
	}
	return &out, nil
}

// --- AnchorHead ---

func latestPtrKey(partition int) string {
	return "partition-" + strconv.Itoa(partition) + "-latest"
}

func (c *ImmudbClient) AnchorHead(ctx context.Context, partition int) (*AnchorPointer, error) {
	entry, err := c.verifiableGet(ctx, latestPtrKey(partition))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	valueBytes, err := base64.StdEncoding.DecodeString(entry.Entry.Value)
	if err != nil {
		return nil, fmt.Errorf("immudb: anchor-head: malformed entry value: %w", err)
	}
	var ptr struct {
		RootID     string `json:"root-id"`
		ToSeq      *int64 `json:"to-seq"`
		NotaryTsTo *int64 `json:"notary-ts-to"`
	}
	if err := json.Unmarshal(valueBytes, &ptr); err != nil {
		// Older entries stored the bare root-id string, not a JSON object --
		// mirror parse-latest-ptr's fallback (immudb.clj).
		return &AnchorPointer{RootID: string(valueBytes), ToSeq: 0}, nil
	}
	toSeq := int64(0)
	if ptr.ToSeq != nil {
		toSeq = *ptr.ToSeq
	}
	// notary-ts-to (s-8snm decision 2) is absent/null on a pointer written
	// before this field existed -- left 0, which only ever makes scan step
	// 5's tail check MORE cautious, never less.
	notaryTsTo := int64(0)
	if ptr.NotaryTsTo != nil {
		notaryTsTo = *ptr.NotaryTsTo
	}
	return &AnchorPointer{RootID: ptr.RootID, ToSeq: toSeq, NotaryTsTo: notaryTsTo}, nil
}

// --- SQL discovery index ---

type sqlValue struct {
	S *string `json:"s"`
	// N is immudb's protojson oneof shape for an int64 SQL column value,
	// arriving JSON-encoded as a string -- mirroring sqlParamInt's own
	// request-side encoding.
	N *string `json:"n"`
}

func (v sqlValue) asString() (string, bool) {
	if v.S == nil {
		return "", false
	}
	return *v.S, true
}

func (v sqlValue) asInt64() (int64, bool) {
	if v.N == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(*v.N, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

type sqlQueryResponse struct {
	Rows []struct {
		Values []sqlValue `json:"values"`
	} `json:"rows"`
}

func (c *ImmudbClient) sqlQuery(ctx context.Context, sql string, params []map[string]interface{}) (*sqlQueryResponse, error) {
	body := map[string]interface{}{"sql": sql}
	if len(params) > 0 {
		body["params"] = params
	}
	reqBody, _ := json.Marshal(body)
	resp, err := c.callWithRefresh(ctx, c.BaseURL+"/api/db/sqlquery", reqBody)
	if err != nil {
		return nil, err
	}
	if resp.status != 200 {
		return nil, fmt.Errorf("immudb: sqlquery failed: status %d: %s", resp.status, string(resp.body))
	}
	var out sqlQueryResponse
	if err := json.Unmarshal(resp.body, &out); err != nil {
		return nil, fmt.Errorf("immudb: sqlquery response decode failed: %w", err)
	}
	return &out, nil
}

func sqlParamStr(name, value string) map[string]interface{} {
	return map[string]interface{}{"name": name, "value": map[string]interface{}{"s": value}}
}

func sqlParamInt(name string, value int64) map[string]interface{} {
	return map[string]interface{}{"name": name, "value": map[string]interface{}{"n": strconv.FormatInt(value, 10)}}
}

// rootsWindowPageSize bounds how many discovery-index rows one
// queryRootsIndexPage call requests -- mirrors immudb.clj's
// window-page-size (s-8snm decision 3).
// rootsWindowPageSize is a var, not a const, solely so tests can lower it
// temporarily to exercise multi-page pagination without a thousand-row
// fixture.
var rootsWindowPageSize = 1000

// immudbMaxWindowRoots is a defensive upper bound on the number of roots
// EnumerateRootsInWindow will produce for one window before returning an
// error -- not an expected window size (a caller narrows the window
// instead), but a guard against an accidentally-unbounded window being
// fully materialized. Checked incrementally, page by page. Mirrors
// mpe-iam-lite's notary/anchor/immudb.clj max-window-roots convention
// (s-8snm decision 3: throw, never silently truncate). A var, not a const,
// solely so tests can lower it temporarily rather than fabricate a
// million-row fixture.
var immudbMaxWindowRoots = 1_000_000

// immudbMaxChainWalkSteps bounds how many backward prev_root_id hops the
// chain-walk fallback (recoverChainGaps) will take to repair a single
// detected gap between the SQL-derived discovery-index enumeration and
// AnchorHead/a neighboring root's own claimed predecessor -- never an
// unconditional, on-every-scan walk (s-5910 constraint 3). Same
// throw-never-silently-truncate convention and var-not-const rationale as
// immudbMaxWindowRoots.
var immudbMaxChainWalkSteps = 1_000_000

// windowRow is one (notary_ts_to, root_id) row from the discovery index --
// the composite keyset cursor queryRootsIndexPage's pagination advances by.
type windowRow struct {
	notaryTsTo int64
	rootID     string
}

// queryRootsIndexPage fetches one page (at most limit rows) of the
// discovery index for partition's roots whose notary_ts_to falls in
// [fromTS, toTS), ordered ascending by (notary_ts_to, root_id) -- the same
// composite ordering mpe-iam-lite's query-roots-index-page uses, so a
// notary_ts_to tie never causes a skipped or duplicated row across pages.
// after, when non-nil, is the previous page's last row; only rows strictly
// greater than that composite key are returned.
func (c *ImmudbClient) queryRootsIndexPage(ctx context.Context, partition int, fromTS, toTS int64, after *windowRow, limit int) ([]windowRow, error) {
	sql := "SELECT notary_ts_to, root_id FROM " + rootsIndexTable +
		" WHERE partition_id = @partition_id" +
		" AND notary_ts_to >= @from_ts AND notary_ts_to < @to_ts"
	params := []map[string]interface{}{
		sqlParamStr("partition_id", strconv.Itoa(partition)),
		sqlParamInt("from_ts", fromTS),
		sqlParamInt("to_ts", toTS),
	}
	if after != nil {
		sql += " AND (notary_ts_to > @after_ts OR (notary_ts_to = @after_ts AND root_id > @after_root_id))"
		params = append(params,
			sqlParamInt("after_ts", after.notaryTsTo),
			sqlParamStr("after_root_id", after.rootID),
		)
	}
	sql += " ORDER BY notary_ts_to, root_id LIMIT " + strconv.Itoa(limit)

	resp, err := c.sqlQuery(ctx, sql, params)
	if err != nil {
		return nil, err
	}
	rows := make([]windowRow, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		if len(row.Values) < 2 {
			continue
		}
		notaryTsTo, ok1 := row.Values[0].asInt64()
		rootID, ok2 := row.Values[1].asString()
		if !ok1 || !ok2 {
			continue
		}
		rows = append(rows, windowRow{notaryTsTo: notaryTsTo, rootID: rootID})
	}
	return rows, nil
}

// rootsInWindow enumerates partition's root-ids whose notary_ts_to falls in
// [fromTS, toTS), ordered ascending, paginating the discovery index via a
// (notary_ts_to, root_id) keyset cursor one page at a time -- bounded by
// immudbMaxWindowRoots (s-8snm decision 3).
func (c *ImmudbClient) rootsInWindow(ctx context.Context, partition int, fromTS, toTS int64) ([]string, error) {
	var (
		rootIDs []string
		after   *windowRow
	)
	for {
		page, err := c.queryRootsIndexPage(ctx, partition, fromTS, toTS, after, rootsWindowPageSize)
		if err != nil {
			return nil, fmt.Errorf("immudb: enumerate-roots-in-window: discovery index query failed: %w", err)
		}
		for _, row := range page {
			rootIDs = append(rootIDs, row.rootID)
		}
		if len(rootIDs) > immudbMaxWindowRoots {
			return nil, fmt.Errorf("immudb: enumerate-roots-in-window: partition %d window [%d,%d) exceeds immudbMaxWindowRoots (%d); narrow the window",
				partition, fromTS, toTS, immudbMaxWindowRoots)
		}
		if len(page) < rootsWindowPageSize {
			return rootIDs, nil
		}
		last := page[len(page)-1]
		after = &last
	}
}

// fetchRoot fetches and JSON-decodes one root via verifiable/get -- the same
// trust boundary as inclusion-anchor's cache-miss path. Returns (nil, nil)
// when the key is genuinely absent from the verified KV store (immudb's
// key-not-found?), leaving the caller to decide what that absence means in
// its own context (a corrupted discovery-index row vs. a genuinely missing
// chain predecessor).
func (c *ImmudbClient) fetchRoot(ctx context.Context, rootID string) (*EnumeratedRoot, error) {
	entry, err := c.verifiableGet(ctx, rootID)
	if err != nil {
		return nil, fmt.Errorf("immudb: enumerate-roots-in-window: fetch of root %q failed: %w", rootID, err)
	}
	if entry == nil {
		return nil, nil
	}
	valueBytes, err := base64.StdEncoding.DecodeString(entry.Entry.Value)
	if err != nil {
		return nil, fmt.Errorf("immudb: enumerate-roots-in-window: malformed value for root %q: %w", rootID, err)
	}
	payload, err := decodeJSONMap(valueBytes)
	if err != nil {
		return nil, fmt.Errorf("immudb: enumerate-roots-in-window: payload decode failed for root %q: %w", rootID, err)
	}
	return &EnumeratedRoot{RootID: rootID, Payload: payload}, nil
}

// fetchRoots fetches and decodes every rootID named by the SQL discovery
// index. A rootID the index named but verifiable/get cannot find is a
// corrupted index row -- distinct from recoverChainGaps' genuine-absence
// case below, since here the index positively asserted the root exists.
func (c *ImmudbClient) fetchRoots(ctx context.Context, rootIDs []string) ([]EnumeratedRoot, error) {
	out := make([]EnumeratedRoot, 0, len(rootIDs))
	for _, rootID := range rootIDs {
		r, err := c.fetchRoot(ctx, rootID)
		if err != nil {
			return nil, err
		}
		if r == nil {
			return nil, fmt.Errorf("immudb: enumerate-roots-in-window: discovery index named root %q but verifiable/get found nothing (corrupted index row)", rootID)
		}
		out = append(out, *r)
	}
	return out, nil
}

// recoverChainGaps repairs the specific, narrow failure mode s-5910
// documents: a notary_root_index row for an otherwise durably-anchored root
// went silently missing (a real, independently-tracked write-path bug on
// the mpe-iam-lite side -- see s-7ykm), which would otherwise surface as a
// false tamper (chain/contiguity) finding rather than as what it actually
// is -- an index bookkeeping gap.
//
// It is only ever triggered by a concrete mismatch -- AnchorHead's own
// root-id missing from the tail, or one root's claimed prev_root_id not
// matching its immediate predecessor in the SQL-derived list -- never
// unconditionally, and each triggered walk is bounded by
// immudbMaxChainWalkSteps (shared across every walk performed by one
// EnumerateRootsInWindow call). A walked-to candidate is fetched fresh from
// the verified KV store (the same call VerifyAnchorProof itself uses) and
// returned as an ordinary EnumeratedRoot -- it is never accepted purely on
// the walk's say-so; it still goes through the exact same root-signature
// (scan step 2a) and anchor-inclusion-proof (scan step 3) checks the caller
// already applies to every other enumerated root.
//
// If a walk's next hop is genuinely absent from the verified KV store --
// named by a neighbor's own prev_root_id, not merely missing from the
// discovery index -- that is real tamper evidence, not a recoverable gap,
// and is returned as a hard error rather than being silently swallowed.
func (c *ImmudbClient) recoverChainGaps(ctx context.Context, partition int, fromTS, toTS int64, roots []EnumeratedRoot) ([]EnumeratedRoot, error) {
	head, err := c.AnchorHead(ctx, partition)
	if err != nil {
		return nil, fmt.Errorf("immudb: enumerate-roots-in-window: anchor-head lookup failed: %w", err)
	}

	result := make([]EnumeratedRoot, len(roots))
	copy(result, roots)

	steps := 0
	// walk fetches backward from startRootID via each hop's own prev_root_id
	// until it reaches reconnectID (already-known, so trusted without
	// re-fetching), or -- only when reconnectID is "" -- the window's own
	// floor (notary_ts_to < fromTS) or a genesis root (no predecessor).
	// Returns the recovered chain ascending by notary_ts_to. A reconnectID
	// that is never reached before the chain runs out (floor or genesis) is
	// an irreconcilable inconsistency between the index and the signed
	// chain, not a gap this fallback can safely paper over.
	walk := func(startRootID, reconnectID string) ([]EnumeratedRoot, error) {
		var gap []EnumeratedRoot
		cursor := startRootID
		for {
			if reconnectID != "" && cursor == reconnectID {
				return gap, nil
			}
			steps++
			if steps > immudbMaxChainWalkSteps {
				return nil, fmt.Errorf("immudb: enumerate-roots-in-window: chain-walk fallback exceeded immudbMaxChainWalkSteps (%d) for partition %d window [%d,%d); the discovery index and the prev_root_id chain have diverged too far to safely reconcile",
					immudbMaxChainWalkSteps, partition, fromTS, toTS)
			}
			candidate, err := c.fetchRoot(ctx, cursor)
			if err != nil {
				return nil, err
			}
			if candidate == nil {
				return nil, fmt.Errorf("immudb: enumerate-roots-in-window: predecessor root-id %q does not exist in the anchor's verified store (named by a neighboring root's own prev_root_id; this is genuine absence, not a discovery-index bookkeeping gap)", cursor)
			}
			if ts, ok := getInt64(candidate.Payload, "notary_ts_to"); reconnectID == "" && ok && ts < fromTS {
				return gap, nil // legitimate window-floor boundary, mirrors scan.go's own first-root prev_root_id caveat
			}
			gap = append([]EnumeratedRoot{*candidate}, gap...) // prepend: cursor walks high-to-low ts, gap stays ascending
			prevID, _ := getString(candidate.Payload, "prev_root_id")
			if prevID == "" {
				if reconnectID != "" {
					return nil, fmt.Errorf("immudb: enumerate-roots-in-window: chain-walk fallback reached a genesis root (%q) without ever reaching expected predecessor %q; the discovery index and the signed chain are irreconcilable", cursor, reconnectID)
				}
				return gap, nil
			}
			cursor = prevID
		}
	}

	// Tail gap: AnchorHead is the authoritative "last root" whenever it
	// falls inside this window (mirrors scan.go step 5's own head-inside-
	// window test) -- if the SQL-derived list doesn't already end there,
	// walk backward from head to recover whatever the index silently
	// dropped off the tail.
	if head != nil && head.NotaryTsTo >= fromTS && head.NotaryTsTo < toTS &&
		(len(result) == 0 || result[len(result)-1].RootID != head.RootID) {
		reconnect := ""
		if len(result) > 0 {
			reconnect = result[len(result)-1].RootID
		}
		gap, err := walk(head.RootID, reconnect)
		if err != nil {
			return nil, err
		}
		result = append(result, gap...)
	}

	// Internal gaps: verify every remaining pairwise link in the SQL-derived
	// (plus any tail-recovered) list, splicing in a walk-recovered run
	// wherever a link is broken.
	for i := len(result) - 1; i > 0; i-- {
		expectedPrevID, _ := getString(result[i].Payload, "prev_root_id")
		if expectedPrevID == result[i-1].RootID {
			continue
		}
		gap, err := walk(expectedPrevID, result[i-1].RootID)
		if err != nil {
			return nil, err
		}
		merged := make([]EnumeratedRoot, 0, len(result)+len(gap))
		merged = append(merged, result[:i]...)
		merged = append(merged, gap...)
		merged = append(merged, result[i:]...)
		result = merged
	}

	// Leading gap: the very first (lowest notary_ts_to) entry has no
	// predecessor in our own list to compare against, so check its own
	// prev_root_id directly -- walk stops immediately, cheaply, at the
	// window floor when this is an ordinary boundary rather than a gap.
	if len(result) > 0 {
		if firstPrevID, ok := getString(result[0].Payload, "prev_root_id"); ok && firstPrevID != "" {
			gap, err := walk(firstPrevID, "")
			if err != nil {
				return nil, err
			}
			result = append(gap, result...)
		}
	}

	if len(result) > immudbMaxWindowRoots {
		return nil, fmt.Errorf("immudb: enumerate-roots-in-window: partition %d window [%d,%d) exceeds immudbMaxWindowRoots (%d) after chain-walk recovery; narrow the window",
			partition, fromTS, toTS, immudbMaxWindowRoots)
	}
	return result, nil
}

// EnumerateRootsInWindow queries the untrusted (partition, notary_ts_to,
// root_id) discovery index for candidate root-ids in [fromTS, toTS), fetches
// and JSON-decodes each hit via verifiable/get, and then runs
// recoverChainGaps to repair the specific case where the index silently
// dropped a row for a root that is still genuinely, durably anchored (s-5910)
// -- since the index is never trusted as the sole source of truth. Any other
// corrupted/omitted index row (fetchRoots) or genuinely absent chain
// predecessor (recoverChainGaps) still surfaces as a hard error, never a
// silent truncation.
func (c *ImmudbClient) EnumerateRootsInWindow(ctx context.Context, partition int, fromTS, toTS int64) ([]EnumeratedRoot, error) {
	rootIDs, err := c.rootsInWindow(ctx, partition, fromTS, toTS)
	if err != nil {
		return nil, err
	}
	out, err := c.fetchRoots(ctx, rootIDs)
	if err != nil {
		return nil, err
	}
	return c.recoverChainGaps(ctx, partition, fromTS, toTS, out)
}

// --- immudb ALH recomputation (self-contained; mirrors
// pkg/audit/verify's ComputeImmudbALH byte-for-byte, kept independent so
// this package has no dependency on that package's unexported field-struct
// shape) ---

func concatBytes(bs ...[]byte) []byte {
	n := 0
	for _, b := range bs {
		n += len(b)
	}
	out := make([]byte, 0, n)
	for _, b := range bs {
		out = append(out, b...)
	}
	return out
}

func longToBEBytes(n int64) []byte {
	b := make([]byte, 8)
	u := uint64(n) // #nosec G115 -- lossless bit-pattern reinterpretation
	for i := 7; i >= 0; i-- {
		b[i] = byte(u)
		u >>= 8
	}
	return b
}

func intToBEBytes(n int64) []byte {
	b := make([]byte, 4)
	u := uint32(n) // #nosec G115 -- lossless bit-pattern reinterpretation
	for i := 3; i >= 0; i-- {
		b[i] = byte(u)
		u >>= 8
	}
	return b
}

func shortToBEBytes(n int64) []byte {
	b := make([]byte, 2)
	u := uint16(n) // #nosec G115 -- lossless bit-pattern reinterpretation
	b[1] = byte(u) // #nosec G115 -- lossless bit-pattern reinterpretation
	b[0] = byte(u >> 8)
	return b
}

var zeroHash32 = make([]byte, 32)

type immudbALHFields struct {
	TxID     int64
	PrevALH  []byte
	TS       int64
	Version  int64
	Nentries int64
	EH       []byte
	BlTxID   int64
	BlRoot   []byte
	Metadata []byte
}

// innerHash computes immudb's TxHeader.innerHash, mirroring
// pkg/audit/verify.go's unexported immudbInnerHash.
func innerHash(f immudbALHFields) []byte {
	md := f.Metadata
	if md == nil {
		md = []byte{}
	}
	versionBytes := shortToBEBytes(f.Version)
	var mid []byte
	if f.Version == 0 {
		mid = shortToBEBytes(f.Nentries)
	} else {
		mdLen := shortToBEBytes(int64(len(md)))
		nentriesBytes := intToBEBytes(f.Nentries)
		mid = concatBytes(mdLen, md, nentriesBytes)
	}
	h := sha256.Sum256(concatBytes(longToBEBytes(f.TS), versionBytes, mid, f.EH, longToBEBytes(f.BlTxID), f.BlRoot))
	return h[:]
}

// computeImmudbALH recomputes immudb's TxHeader.Alh:
// sha256(txID(8BE) || prevAlh(32) || innerHash(32)).
func computeImmudbALH(f immudbALHFields) []byte {
	inner := innerHash(f)
	h := sha256.Sum256(concatBytes(longToBEBytes(f.TxID), f.PrevALH, inner))
	return h[:]
}

// parseTxHeader converts the grpc-gateway JSON TxHeader into immudbALHFields,
// mirroring immudb.clj's parse-tx-header: absent hashes default to the
// 32-zero digest (grpc-gateway omitempty), and a header carrying non-empty
// metadata is not ALH-recomputable from its JSON projection.
func parseTxHeader(h immudbTxHeader) (immudbALHFields, error) {
	if h.EH == "" {
		return immudbALHFields{}, fmt.Errorf("immudb: tx header has no eH; cannot recompute ALH")
	}
	if len(h.Metadata) > 0 && string(h.Metadata) != "null" && strings.TrimSpace(string(h.Metadata)) != "{}" {
		return immudbALHFields{}, fmt.Errorf("immudb: tx header carries non-empty metadata; not ALH-recomputable from its JSON projection")
	}
	eh, err := base64.StdEncoding.DecodeString(h.EH)
	if err != nil {
		return immudbALHFields{}, fmt.Errorf("immudb: malformed eH: %w", err)
	}
	prevAlh := zeroHash32
	if h.PrevAlh != "" {
		prevAlh, err = base64.StdEncoding.DecodeString(h.PrevAlh)
		if err != nil {
			return immudbALHFields{}, fmt.Errorf("immudb: malformed prevAlh: %w", err)
		}
	}
	blRoot := zeroHash32
	if h.BlRoot != "" {
		blRoot, err = base64.StdEncoding.DecodeString(h.BlRoot)
		if err != nil {
			return immudbALHFields{}, fmt.Errorf("immudb: malformed blRoot: %w", err)
		}
	}
	return immudbALHFields{
		TxID:     headerLong(h.ID),
		PrevALH:  prevAlh,
		TS:       headerLong(h.TS),
		Version:  headerLong(h.Version),
		Nentries: headerLong(h.Nentries),
		EH:       eh,
		BlTxID:   headerLong(h.BlTxID),
		BlRoot:   blRoot,
	}, nil
}

// immudbHTreeLeaf computes immudb's HTree leaf hash for a (key, value) KV
// entry: sha256(sha256(key) || sha256(value)) -- mirrors
// notary/verify.clj's immudb-htree-leaf / immudb.clj's immudb-entry-hash.
func immudbHTreeLeaf(keyBytes, valueBytes []byte) []byte {
	kh := sha256.Sum256(keyBytes)
	vh := sha256.Sum256(valueBytes)
	h := sha256.Sum256(concatBytes(kh[:], vh[:]))
	return h[:]
}

// AnchorRef fetches and assembles the immudb anchor_refs.immudb map for
// root -- the same material VerifyAnchorProof cryptographically checks,
// exposed so a caller (e.g. BuildCounterExampleBundle) can embed genuine,
// independently re-verifiable proof material into a portable bundle rather
// than a bare re-assertion of "verified".
func (c *ImmudbClient) AnchorRef(ctx context.Context, root EnumeratedRoot) (map[string]interface{}, error) {
	entry, err := c.verifiableGet(ctx, root.RootID)
	if err != nil {
		return nil, fmt.Errorf("immudb: anchor-ref: fetch failed for root %q: %w", root.RootID, err)
	}
	if entry == nil {
		return nil, newProofFailure("root %q not found in immudb KV store", root.RootID)
	}
	valueBytes, err := base64.StdEncoding.DecodeString(entry.Entry.Value)
	if err != nil {
		return nil, newProofFailure("malformed entry value for root %q: %v", root.RootID, err)
	}
	header := entry.VerifiableTx.Tx.Header
	fields, err := parseTxHeader(header)
	if err != nil {
		return nil, newProofFailure("%v", err)
	}
	alh := computeImmudbALH(fields)
	entryHash := immudbHTreeLeaf([]byte(root.RootID), valueBytes)

	inclusionProof := entry.InclusionProof.Terms
	proofIfc := make([]interface{}, len(inclusionProof))
	for i, s := range inclusionProof {
		proofIfc[i] = s
	}

	txID, _ := header.ID.Int64()
	immudbRef := map[string]interface{}{
		"state_db":        c.Database,
		"tx_id":           num(txID),
		"entry_hash":      b64urlEncode(entryHash),
		"inclusion_proof": proofIfc,
		"tx_nentries":     num(fields.Nentries),
		"tx_eH":           header.EH,
		"tx_hash":         base64.StdEncoding.EncodeToString(alh),
		"state_signature": entry.VerifiableTx.Signature.Signature,
		"tx_ts":           num(fields.TS),
		"tx_version":      num(fields.Version),
		"tx_bl_tx_id":     num(fields.BlTxID),
		"tx_bl_root":      header.BlRoot,
		"tx_prev_alh":     header.PrevAlh,
	}
	return map[string]interface{}{"immudb": immudbRef}, nil
}

// VerifyAnchorProof validates root's immudb anchor-inclusion proof: the
// HTree inclusion proof (entry_hash -> tx_eH), the server's signed
// ImmutableState over (db, tx_id, tx_hash), that tx_hash itself is immudb's
// recomputed ALH (ComputeImmudbALH-equivalent) binding to tx_eH, and that
// entry_hash equals the independently recomputed value from THIS root's own
// root-id/payload -- delegating that full four-part check to
// pkg/audit/verify.VerifyImmudbAnchor, the exact same primitive the offline
// bundle verifier uses, so the two never drift on what "verified" means.
func (c *ImmudbClient) VerifyAnchorProof(ctx context.Context, root EnumeratedRoot, pubKey interface{}) (AnchorProofResult, error) {
	anchorRefs, err := c.AnchorRef(ctx, root)
	if err != nil {
		var pf *proofFailure
		if errors.As(err, &pf) {
			return AnchorProofResult{OK: false, Detail: pf.Error()}, nil
		}
		return AnchorProofResult{}, fmt.Errorf("immudb: verify-anchor-proof: %w", err)
	}
	result := verify.VerifyImmudbAnchor(anchorRefs, pubKey, true, root.RootID, root.Payload)
	return AnchorProofResult{OK: result.Status == verify.AnchorVerified, Detail: result.Detail}, nil
}

var _ AnchorClient = (*ImmudbClient)(nil)
