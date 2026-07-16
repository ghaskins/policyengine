//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/manetu/policyengine/pkg/audit/verify"
)

// s3API is the subset of *s3.Client this package calls, so tests can supply
// a fake without a real S3/MinIO endpoint.
type s3API interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// S3Client is a direct client for the S3-compatible (AWS S3, MinIO, Ceph
// RGW, ...) WORM anchor backend, mirroring mpe-iam-lite's
// notary/anchor/s3.clj key layout and enumeration exactly:
// roots/<partition>/<19-digit-zero-padded-notary_ts_to>-<root_id>.json,
// enumerated via ListObjectsV2(prefix, start-after); the per-partition
// "latest" pointer at roots/<partition>/latest.json.
type S3Client struct {
	Client s3API
	Bucket string
}

func (c *S3Client) Tier() string { return "s3:provider-trusted-worm" }

const notaryTsPadWidth = 19

func padNotaryTS(ts int64) string {
	return fmt.Sprintf("%0*d", notaryTsPadWidth, ts)
}

func rootsPrefix(partition int) string {
	return "roots/" + strconv.Itoa(partition) + "/"
}

func objectKey(partition int, notaryTsTo int64, rootID string) string {
	return rootsPrefix(partition) + padNotaryTS(notaryTsTo) + "-" + rootID + ".json"
}

func latestPtrObjectKey(partition int) string {
	return rootsPrefix(partition) + "latest.json"
}

// rootKeyToID parses the root-id suffix out of a root object key under
// prefix (roots/<partition>/<padded-ts>-<root_id>.json), or ("", false) if
// key doesn't have that shape -- notably the partition's own latest.json
// pointer, which enumeration must skip rather than mistake for a root.
func rootKeyToID(prefix, key string) (string, bool) {
	if !strings.HasPrefix(key, prefix) {
		return "", false
	}
	suffix := key[len(prefix):]
	if len(suffix) < notaryTsPadWidth+1 || suffix[notaryTsPadWidth] != '-' {
		return "", false
	}
	tsStr := suffix[:notaryTsPadWidth]
	for _, r := range tsStr {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	rest := suffix[notaryTsPadWidth+1:]
	rootID := strings.TrimSuffix(rest, ".json")
	if rootID == rest {
		return "", false // no .json suffix -- not a root object key
	}
	return rootID, true
}

func rootKeyToNotaryTS(prefix, key string) (int64, bool) {
	if !strings.HasPrefix(key, prefix) {
		return 0, false
	}
	suffix := key[len(prefix):]
	if len(suffix) < notaryTsPadWidth+1 || suffix[notaryTsPadWidth] != '-' {
		return 0, false
	}
	tsStr := suffix[:notaryTsPadWidth]
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return 0, false
	}
	return ts, true
}

func (c *S3Client) getObject(ctx context.Context, key string) ([]byte, error) {
	out, err := c.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: &c.Bucket, Key: &key})
	if err != nil {
		return nil, err
	}
	defer func() { _ = out.Body.Close() }()
	return io.ReadAll(out.Body)
}

func (c *S3Client) AnchorHead(ctx context.Context, partition int) (*AnchorPointer, error) {
	key := latestPtrObjectKey(partition)
	body, err := c.getObject(ctx, key)
	if err != nil {
		if isS3NotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("s3: anchor-head: get-object failed for %q: %w", key, err)
	}
	m, err := decodeJSONMap(body)
	if err != nil {
		return nil, fmt.Errorf("s3: anchor-head: malformed pointer object %q: %w", key, err)
	}
	rootID, _ := getString(m, "root-id")
	toSeq, _ := getInt64(m, "to-seq")
	// notary-ts-to (s-8snm decision 2) is absent on a pointer written before
	// this field existed -- getInt64 returning !ok simply leaves it 0, which
	// only ever makes scan step 5's tail check MORE cautious, never less.
	notaryTsTo, _ := getInt64(m, "notary-ts-to")
	return &AnchorPointer{RootID: rootID, ToSeq: toSeq, NotaryTsTo: notaryTsTo}, nil
}

// isS3NotFound reports whether err is an S3 "no such key" condition. Kept as
// a narrow helper (rather than a generic status-code check) since the SDK
// surfaces this a few different ways depending on transport.
func isS3NotFound(err error) bool {
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	return strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "404")
}

// s3MaxWindowRoots is a defensive upper bound on the number of roots
// EnumerateRootsInWindow will produce for one window before returning an
// error -- not an expected window size (a caller narrows the window
// instead), but a guard against an accidentally-unbounded window (e.g.
// [0, math.MaxInt64)) being fully materialized. Checked incrementally as
// each ListObjectsV2 page's keys are collected, so a request that would
// exceed it fails before a single object in an oversized window is fetched
// -- mirrors mpe-iam-lite's notary/anchor/s3.clj max-window-roots convention
// (s-8snm decision 3: throw, never silently truncate). A var, not a const,
// solely so tests can lower it temporarily rather than fabricate a
// million-object fixture.
var s3MaxWindowRoots = 1_000_000

// EnumerateRootsInWindow lists roots/<partition>/ object keys with
// notary_ts_to in [fromTS, toTS), paginating ListObjectsV2 and stopping as
// soon as a page reaches the toTS boundary -- mirroring
// notary/anchor/s3.clj's collect-window-keys/window-keys-and-done?. Bounded
// by s3MaxWindowRoots (s-8snm decision 3), checked during key collection so an
// oversized window fails before any GetObject is issued.
func (c *S3Client) EnumerateRootsInWindow(ctx context.Context, partition int, fromTS, toTS int64) ([]EnumeratedRoot, error) {
	prefix := rootsPrefix(partition)
	startAfter := prefix + padNotaryTS(fromTS)

	var keys []string
	var token *string
	for {
		in := &s3.ListObjectsV2Input{Bucket: &c.Bucket, Prefix: &prefix}
		if token != nil {
			in.ContinuationToken = token
		} else {
			in.StartAfter = &startAfter
		}
		out, err := c.Client.ListObjectsV2(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("s3: enumerate-roots-in-window: list-objects-v2 failed: %w", err)
		}
		done := false
		for _, obj := range out.Contents {
			key := *obj.Key
			ts, ok := rootKeyToNotaryTS(prefix, key)
			if !ok {
				continue // e.g. the partition's own latest.json pointer
			}
			if ts >= toTS {
				done = true
				break
			}
			keys = append(keys, key)
			if len(keys) > s3MaxWindowRoots {
				return nil, fmt.Errorf("s3: enumerate-roots-in-window: partition %d window [%d,%d) exceeds s3MaxWindowRoots (%d); narrow the window",
					partition, fromTS, toTS, s3MaxWindowRoots)
			}
		}
		if done || out.IsTruncated == nil || !*out.IsTruncated {
			break
		}
		token = out.NextContinuationToken
	}

	out := make([]EnumeratedRoot, 0, len(keys))
	for _, key := range keys {
		rootID, ok := rootKeyToID(prefix, key)
		if !ok {
			continue
		}
		body, err := c.getObject(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("s3: enumerate-roots-in-window: get-object failed for %q: %w", key, err)
		}
		m, err := decodeJSONMap(body)
		if err != nil {
			return nil, fmt.Errorf("s3: enumerate-roots-in-window: malformed root object %q: %w", key, err)
		}
		out = append(out, EnumeratedRoot{RootID: rootID, Payload: m})
	}
	return out, nil
}

// s3ProofFetch is the outcome of re-fetching a root's WORM object for
// binding verification: the fetched bytes' own server-computed checksum, the
// object's WORM (object-lock) state, and its version-id (for a
// version-pinned anchor_refs.s3 ref).
type s3ProofFetch struct {
	key               string
	versionID         string
	checksumSHA256B64 string
	ok                bool
	detail            string
}

// fetchAndCheckProof refetches the exact WORM object root was anchored at,
// requiring the S3-computed checksum(SHA256) of the returned bytes
// (validated server-side by S3/MinIO at upload and echoed back on every
// GetObject) to match a fresh recompute over the same bytes -- proving the
// object handed back on THIS read is bit-for-bit what the server
// independently checksummed at write time -- and requiring active WORM
// protection (Object Lock COMPLIANCE mode with a still-future retain-until
// date, or an active legal hold for a retain-all-policy root) to genuinely
// be set on this specific object, not merely configured at the bucket level.
func (c *S3Client) fetchAndCheckProof(ctx context.Context, root EnumeratedRoot) (s3ProofFetch, error) {
	notaryTsTo, _ := getInt64(root.Payload, "notary_ts_to")
	partition, _ := getInt64(root.Payload, "partition")
	key := objectKey(int(partition), notaryTsTo, root.RootID)

	out, err := c.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket:       &c.Bucket,
		Key:          &key,
		ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil {
		return s3ProofFetch{}, fmt.Errorf("get-object failed for %q: %w", key, err)
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return s3ProofFetch{}, fmt.Errorf("read body failed for %q: %w", key, err)
	}

	versionID := ""
	if out.VersionId != nil {
		versionID = *out.VersionId
	}

	if out.ChecksumSHA256 == nil {
		return s3ProofFetch{key: key, versionID: versionID, ok: false,
			detail: "s3 object carries no server-side ChecksumSHA256 (uploaded without checksum validation); cannot bind fetched bytes to the server's own record"}, nil
	}
	sum := sha256.Sum256(body)
	computed := base64.StdEncoding.EncodeToString(sum[:])
	if computed != *out.ChecksumSHA256 {
		return s3ProofFetch{key: key, versionID: versionID, checksumSHA256B64: *out.ChecksumSHA256, ok: false,
			detail: "s3 object's server-side ChecksumSHA256 does not match the fetched bytes"}, nil
	}

	retainAll := false
	if rp, ok := getMap(root.Payload, "retention_policy"); ok {
		if mode, ok := getString(rp, "mode"); ok && mode == "retain-all" {
			retainAll = true
		}
	}
	worm := false
	switch {
	case retainAll:
		worm = out.ObjectLockLegalHoldStatus == types.ObjectLockLegalHoldStatusOn
	default:
		worm = out.ObjectLockMode == types.ObjectLockModeCompliance &&
			out.ObjectLockRetainUntilDate != nil &&
			out.ObjectLockRetainUntilDate.After(time.Now())
	}
	if !worm {
		return s3ProofFetch{key: key, versionID: versionID, checksumSHA256B64: *out.ChecksumSHA256, ok: false,
			detail: "s3 object is not under active WORM protection (missing/expired object-lock retention or legal hold)"}, nil
	}

	return s3ProofFetch{key: key, versionID: versionID, checksumSHA256B64: *out.ChecksumSHA256, ok: true,
		detail: "s3 object checksum + active WORM protection verified"}, nil
}

// VerifyAnchorProof validates root's S3 anchor binding (see
// fetchAndCheckProof). pubKey is unused for this tier (S3's binding is a
// pure function of the object's own bytes -- no out-of-band signing key is
// involved).
func (c *S3Client) VerifyAnchorProof(ctx context.Context, root EnumeratedRoot, _ interface{}) (AnchorProofResult, error) {
	pf, err := c.fetchAndCheckProof(ctx, root)
	if err != nil {
		return AnchorProofResult{}, fmt.Errorf("s3: verify-anchor-proof: %w", err)
	}
	return AnchorProofResult{OK: pf.ok, Detail: pf.detail}, nil
}

// AnchorRef fetches and assembles the anchor_refs.s3 map for root -- the
// bucket/key/version-id plus the content_sha256 offline binding (base64 of
// sha256 over the canonical signable subset -- the same value
// pkg/audit/verify's expected-s3-content-sha256/verify-s3-anchor
// recomputes), so a counter-example bundle can carry a genuinely
// re-verifiable S3 anchor ref rather than a bare assertion.
func (c *S3Client) AnchorRef(ctx context.Context, root EnumeratedRoot) (map[string]interface{}, error) {
	pf, err := c.fetchAndCheckProof(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("s3: anchor-ref: %w", err)
	}
	canonical, err := verify.CanonicalJSONBytes(selectSignableFields(root.Payload))
	if err != nil {
		return nil, fmt.Errorf("s3: anchor-ref: canonical JSON encode failed: %w", err)
	}
	sum := sha256.Sum256(canonical)
	s3Ref := map[string]interface{}{
		"bucket":         c.Bucket,
		"key":            pf.key,
		"version_id":     pf.versionID,
		"content_sha256": base64.StdEncoding.EncodeToString(sum[:]),
	}
	return map[string]interface{}{"s3": s3Ref}, nil
}

var _ AnchorClient = (*S3Client)(nil)
