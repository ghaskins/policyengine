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
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObjectKeyRoundTrip(t *testing.T) {
	key := objectKey(3, 1700000000123, "root-abc")
	prefix := rootsPrefix(3)
	rootID, ok := rootKeyToID(prefix, key)
	require.True(t, ok)
	assert.Equal(t, "root-abc", rootID)
	ts, ok := rootKeyToNotaryTS(prefix, key)
	require.True(t, ok)
	assert.Equal(t, int64(1700000000123), ts)
}

func TestRootKeyToIDSkipsLatestPointer(t *testing.T) {
	prefix := rootsPrefix(3)
	_, ok := rootKeyToID(prefix, latestPtrObjectKey(3))
	assert.False(t, ok)
	_, ok = rootKeyToNotaryTS(prefix, latestPtrObjectKey(3))
	assert.False(t, ok)
}

func TestPadNotaryTSPreservesNumericOrder(t *testing.T) {
	shorter := padNotaryTS(999999999999)
	longer := padNotaryTS(1000000000000)
	assert.Less(t, shorter, longer, "lexicographic order of the padded strings must match numeric order")
}

// fakeS3API is an in-memory s3API, keyed by object key.
type fakeS3API struct {
	objects map[string]fakeS3Object
}

type fakeS3Object struct {
	body           []byte
	checksumSHA256 string
	lockMode       types.ObjectLockMode
	retainUntil    *time.Time
	legalHold      types.ObjectLockLegalHoldStatus
	versionID      string
}

func newFakeS3API() *fakeS3API { return &fakeS3API{objects: map[string]fakeS3Object{}} }

func (f *fakeS3API) putWORM(key string, body []byte, retainUntil time.Time) {
	sum := sha256.Sum256(body)
	f.objects[key] = fakeS3Object{
		body:           body,
		checksumSHA256: base64.StdEncoding.EncodeToString(sum[:]),
		lockMode:       types.ObjectLockModeCompliance,
		retainUntil:    &retainUntil,
		versionID:      "v1",
	}
}

func (f *fakeS3API) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	obj, ok := f.objects[*in.Key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	out := &s3.GetObjectOutput{
		Body:                      io.NopCloser(bytes.NewReader(obj.body)),
		ObjectLockMode:            obj.lockMode,
		ObjectLockRetainUntilDate: obj.retainUntil,
		ObjectLockLegalHoldStatus: obj.legalHold,
	}
	if obj.versionID != "" {
		out.VersionId = aws.String(obj.versionID)
	}
	if in.ChecksumMode == types.ChecksumModeEnabled && obj.checksumSHA256 != "" {
		out.ChecksumSHA256 = aws.String(obj.checksumSHA256)
	}
	return out, nil
}

func (f *fakeS3API) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	var keys []string
	for k := range f.objects {
		keys = append(keys, k)
	}
	// simple insertion-order-independent sort (keys are fixed-width padded,
	// so lexicographic sort matches numeric notary_ts order)
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	var contents []types.Object
	for _, k := range keys {
		if in.Prefix != nil && len(*in.Prefix) > 0 && !hasPrefix(k, *in.Prefix) {
			continue
		}
		if in.StartAfter != nil && k <= *in.StartAfter {
			continue
		}
		kk := k
		contents = append(contents, types.Object{Key: &kk})
	}
	falseVal := false
	return &s3.ListObjectsV2Output{Contents: contents, IsTruncated: &falseVal}, nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestS3EnumerateRootsInWindow(t *testing.T) {
	api := newFakeS3API()
	until := time.Now().Add(24 * time.Hour)
	root1 := map[string]interface{}{"root_hash_b64": "abc", "partition": 0, "notary_ts_to": 100}
	body1, _ := json.Marshal(root1)
	api.putWORM(objectKey(0, 100, "root-a"), body1, until)
	root2 := map[string]interface{}{"root_hash_b64": "def", "partition": 0, "notary_ts_to": 200}
	body2, _ := json.Marshal(root2)
	api.putWORM(objectKey(0, 200, "root-b"), body2, until)
	// A root outside the requested window must not be returned.
	root3 := map[string]interface{}{"root_hash_b64": "ghi", "partition": 0, "notary_ts_to": 999}
	body3, _ := json.Marshal(root3)
	api.putWORM(objectKey(0, 999, "root-c"), body3, until)

	client := &S3Client{Client: api, Bucket: "test"}
	roots, err := client.EnumerateRootsInWindow(context.Background(), 0, 0, 300)
	require.NoError(t, err)
	require.Len(t, roots, 2)
	assert.Equal(t, "root-a", roots[0].RootID)
	assert.Equal(t, "root-b", roots[1].RootID)
}

func TestS3EnumerateRootsInWindowExceedsCapReturnsError(t *testing.T) {
	orig := s3MaxWindowRoots
	s3MaxWindowRoots = 2
	defer func() { s3MaxWindowRoots = orig }()

	api := newFakeS3API()
	until := time.Now().Add(24 * time.Hour)
	putRoot := func(ts int64, rootID string) {
		root := map[string]interface{}{"root_hash_b64": "h", "partition": 0, "notary_ts_to": ts}
		body, _ := json.Marshal(root)
		api.putWORM(objectKey(0, ts, rootID), body, until)
	}
	putRoot(100, "root-a")
	putRoot(200, "root-b")
	putRoot(300, "root-c") // 3rd root exceeds the lowered cap of 2

	client := &S3Client{Client: api, Bucket: "test"}
	_, err := client.EnumerateRootsInWindow(context.Background(), 0, 0, 1000)
	require.Error(t, err, "an oversized window must throw, never silently truncate (s-8snm decision 3)")
	assert.Contains(t, err.Error(), "exceeds s3MaxWindowRoots")
}

func TestS3AnchorHeadRoundTrip(t *testing.T) {
	api := newFakeS3API()
	until := time.Now().Add(24 * time.Hour)
	ptr := map[string]interface{}{"root-id": "root-z", "to-seq": 42, "notary-ts-to": 99999}
	body, _ := json.Marshal(ptr)
	api.putWORM(latestPtrObjectKey(0), body, until)

	client := &S3Client{Client: api, Bucket: "test"}
	head, err := client.AnchorHead(context.Background(), 0)
	require.NoError(t, err)
	require.NotNil(t, head)
	assert.Equal(t, "root-z", head.RootID)
	assert.Equal(t, int64(42), head.ToSeq)
	assert.Equal(t, int64(99999), head.NotaryTsTo)
}

func TestS3AnchorHeadNotaryTsToAbsentDefaultsZero(t *testing.T) {
	// A pointer written before s-8snm decision 2 has no notary-ts-to key at
	// all -- must decode to 0, not error (a zero value only ever makes scan
	// step 5's tail check MORE cautious, never less).
	api := newFakeS3API()
	until := time.Now().Add(24 * time.Hour)
	ptr := map[string]interface{}{"root-id": "root-old", "to-seq": 7}
	body, _ := json.Marshal(ptr)
	api.putWORM(latestPtrObjectKey(0), body, until)

	client := &S3Client{Client: api, Bucket: "test"}
	head, err := client.AnchorHead(context.Background(), 0)
	require.NoError(t, err)
	require.NotNil(t, head)
	assert.Equal(t, int64(0), head.NotaryTsTo)
}

func TestS3AnchorHeadNilWhenNeverAnchored(t *testing.T) {
	client := &S3Client{Client: newFakeS3API(), Bucket: "test"}
	head, err := client.AnchorHead(context.Background(), 5)
	require.NoError(t, err)
	assert.Nil(t, head)
}

func TestS3VerifyAnchorProofChecksumMismatchFails(t *testing.T) {
	api := newFakeS3API()
	until := time.Now().Add(24 * time.Hour)
	root := normalizeMap(t, map[string]interface{}{
		"root_hash_b64": "abc", "partition": 0, "notary_ts_to": 100,
		"tree_size": 1, "covered_range": map[string]interface{}{"from_seq": 0, "to_seq": 0},
		"retention_policy": map[string]interface{}{"mode": "retain-all"},
	})
	key := objectKey(0, 100, "root-a")
	body, _ := json.Marshal(map[string]interface{}{"root_hash_b64": "abc"})
	api.putWORM(key, body, until)
	api.objects[key] = fakeS3Object{body: body, checksumSHA256: "bm90LXRoZS1yZWFsLXN1bQ==", lockMode: types.ObjectLockModeCompliance, retainUntil: &until, versionID: "v1"}

	client := &S3Client{Client: api, Bucket: "test"}
	result, err := client.VerifyAnchorProof(context.Background(), EnumeratedRoot{RootID: "root-a", Payload: root}, nil)
	require.NoError(t, err)
	assert.False(t, result.OK)
}

func TestS3VerifyAnchorProofExpiredRetentionFails(t *testing.T) {
	api := newFakeS3API()
	expired := time.Now().Add(-24 * time.Hour)
	root := normalizeMap(t, map[string]interface{}{
		"root_hash_b64": "abc", "partition": 0, "notary_ts_to": 100,
		"retention_policy": map[string]interface{}{"mode": "relative", "P": "P6M"},
	})
	key := objectKey(0, 100, "root-a")
	body, _ := json.Marshal(map[string]interface{}{"root_hash_b64": "abc"})
	api.putWORM(key, body, expired)

	client := &S3Client{Client: api, Bucket: "test"}
	result, err := client.VerifyAnchorProof(context.Background(), EnumeratedRoot{RootID: "root-a", Payload: root}, nil)
	require.NoError(t, err)
	assert.False(t, result.OK, "an object whose object-lock has already expired must not read as WORM-protected")
}
