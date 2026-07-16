//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sampleS3SignedRootFixture returns a fixed, arbitrary signed_root map used
// by fixtures/tests below that don't care about the specific root -- only
// that VerifyS3Anchor's content_sha256 binding passes when the fixture and
// the verification call agree on the same signed_root.
func sampleS3SignedRootFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	return normalizeJSON(t, map[string]interface{}{
		"root_hash_b64":      b64urlEnc(LeafHash([]byte("bundle-root"))),
		"tree_size":          1,
		"partition":          0,
		"partition_count":    1,
		"covered_range":      map[string]interface{}{"from_seq": 1, "to_seq": 1},
		"prev_root_hash_b64": nil,
		"prev_root_id":       nil,
		"notary_ts_from":     1700000000000,
		"notary_ts_to":       1700000000000,
		"retention_policy":   map[string]interface{}{"mode": "retain-all"},
	})
}

// buildS3Fixture builds a self-consistent anchor_refs.s3 map: content_sha256
// recomputed from signedRoot exactly as the notary commits it
// (expectedS3ContentSHA256), so it verifies cleanly against that same root.
func buildS3Fixture(t *testing.T, signedRoot map[string]interface{}) map[string]interface{} {
	t.Helper()
	expected, err := expectedS3ContentSHA256(signedRoot)
	require.NoError(t, err)
	return normalizeJSON(t, map[string]interface{}{
		"bucket":         "audit-roots",
		"key":            "roots/0/some-root-id.json",
		"version_id":     "v1",
		"content_sha256": base64.StdEncoding.EncodeToString(expected),
	})
}

func anchorRefsWithS3(s3 map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"s3": s3}
}

func TestVerifyS3AnchorVerified(t *testing.T) {
	t.Parallel()

	signedRoot := sampleS3SignedRootFixture(t)
	s3 := buildS3Fixture(t, signedRoot)
	r := VerifyS3Anchor(anchorRefsWithS3(s3), false, signedRoot)
	assert.Equal(t, AnchorVerified, r.Status, r.Detail)
}

// TestVerifyS3AnchorBoundToDifferentRootFails is the s3 analogue of
// TestVerifyImmudbAnchorBoundToDifferentRootFails: a fully valid,
// self-consistent s3 anchor -- genuinely bound to root A's own signed_root
// -- must FAIL when checked against a different root B, since
// content_sha256 is recomputed from THIS call's signedRoot, not trusted
// as-is.
func TestVerifyS3AnchorBoundToDifferentRootFails(t *testing.T) {
	t.Parallel()

	signedRoot := sampleS3SignedRootFixture(t)
	s3 := buildS3Fixture(t, signedRoot)

	// Sanity: the fixture verifies cleanly against the root it's actually
	// bound to.
	r := VerifyS3Anchor(anchorRefsWithS3(s3), false, signedRoot)
	require.Equal(t, AnchorVerified, r.Status, r.Detail)

	otherSignedRoot := normalizeJSON(t, map[string]interface{}{
		"root_hash_b64":      b64urlEnc(LeafHash([]byte("a-different-bundle-root"))),
		"tree_size":          1,
		"partition":          0,
		"partition_count":    1,
		"covered_range":      map[string]interface{}{"from_seq": 1, "to_seq": 1},
		"prev_root_hash_b64": nil,
		"prev_root_id":       nil,
		"notary_ts_from":     1700000000000,
		"notary_ts_to":       1700000000000,
		"retention_policy":   map[string]interface{}{"mode": "retain-all"},
	})
	r = VerifyS3Anchor(anchorRefsWithS3(s3), false, otherSignedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
	assert.Contains(t, r.Detail, "does not match this bundle's signed_root")
}

func TestVerifyS3AnchorAbsent(t *testing.T) {
	t.Parallel()

	r := VerifyS3Anchor(map[string]interface{}{}, false, sampleS3SignedRootFixture(t))
	assert.Equal(t, AnchorSkipped, r.Status)
}

func TestVerifyS3AnchorAbsentButRequired(t *testing.T) {
	t.Parallel()

	r := VerifyS3Anchor(map[string]interface{}{}, true, sampleS3SignedRootFixture(t))
	assert.Equal(t, AnchorFailed, r.Status)
}

// TestVerifyS3AnchorMissingContentSHA256 confirms that an s3 ref present
// without content_sha256 (the field stripped, or a bundle predating this
// check) is SKIPPED, not VERIFIED -- there is nothing to check.
func TestVerifyS3AnchorMissingContentSHA256(t *testing.T) {
	t.Parallel()

	s3 := normalizeJSON(t, map[string]interface{}{"bucket": "audit-roots", "key": "roots/0/x.json", "version_id": "v1"})
	r := VerifyS3Anchor(anchorRefsWithS3(s3), false, sampleS3SignedRootFixture(t))
	assert.Equal(t, AnchorSkipped, r.Status)
}

// TestVerifyS3AnchorMissingContentSHA256ButRequiredFails is
// TestVerifyS3AnchorMissingContentSHA256's --require-anchor s3 counterpart:
// a stripped binding must fail closed when required, not silently skip.
func TestVerifyS3AnchorMissingContentSHA256ButRequiredFails(t *testing.T) {
	t.Parallel()

	s3 := normalizeJSON(t, map[string]interface{}{"bucket": "audit-roots", "key": "roots/0/x.json", "version_id": "v1"})
	r := VerifyS3Anchor(anchorRefsWithS3(s3), true, sampleS3SignedRootFixture(t))
	assert.Equal(t, AnchorFailed, r.Status)
}

// TestVerifyS3AnchorTamperedContentFailsEvenWithoutRequire is the key
// divergence from immudb/rekor: unlike a keyed anchor, s3's content_sha256
// binding needs no out-of-band trust root, so a present-but-invalid binding
// must fail regardless of --require-anchor -- there is no key to be
// "missing" that would otherwise excuse skipping the check.
func TestVerifyS3AnchorTamperedContentFailsEvenWithoutRequire(t *testing.T) {
	t.Parallel()

	signedRoot := sampleS3SignedRootFixture(t)
	s3 := buildS3Fixture(t, signedRoot)
	s3["content_sha256"] = base64.StdEncoding.EncodeToString(LeafHash([]byte("evil")))
	r := VerifyS3Anchor(anchorRefsWithS3(s3), false, signedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
}

func TestVerifyS3AnchorMalformedBase64FailsClosed(t *testing.T) {
	t.Parallel()

	signedRoot := sampleS3SignedRootFixture(t)
	s3 := buildS3Fixture(t, signedRoot)
	s3["content_sha256"] = invalidBase64
	r := VerifyS3Anchor(anchorRefsWithS3(s3), false, signedRoot)
	assert.Equal(t, AnchorFailed, r.Status)
}

// TestExpectedS3ContentSHA256MatchesImmudbEntryHashInput confirms s3 and
// immudb bind to the exact same canonical value (mirrors immudb's
// entry_hash, per both packages' doc comments) -- only the outer hashing
// (immudb wraps root_id/HTree framing around it; s3 hashes it directly)
// differs.
func TestExpectedS3ContentSHA256MatchesImmudbEntryHashInput(t *testing.T) {
	t.Parallel()

	signedRoot := sampleS3SignedRootFixture(t)
	signable := selectKeys(signedRoot, SignableRootFields)
	valueBytes, err := CanonicalJSONBytes(signable)
	require.NoError(t, err)
	wantSum := sha256.Sum256(valueBytes)

	got, err := expectedS3ContentSHA256(signedRoot)
	require.NoError(t, err)
	assert.Equal(t, wantSum[:], got)
}
