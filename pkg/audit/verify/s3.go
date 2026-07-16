//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// S3Result is the outcome of [VerifyS3Anchor]. Like [ImmudbResult] (and
// unlike the retired RekorResult), Status alone is tri-state
// (verified/failed/skipped) -- there is no separate "OK but skipped" flag.
type S3Result struct {
	Status AnchorStatus
	Detail string
}

// expectedS3ContentSHA256 recomputes the expected S3/MinIO WORM anchor's
// content_sha256 for this bundle's signed_root:
//
//	sha256(CanonicalJSONBytes(selectKeys(signedRoot, SignableRootFields)))
//
// -- the same canonical signable-fields encoding immudb's entry_hash binds
// to (see expectedImmudbEntryHash), mirroring notary/anchor/s3.clj's
// content-sha256. Because signed_root is already present in the bundle, a
// verifier recomputes this directly and rejects a genuine-but-unrelated s3
// object paired with the wrong bundle.
func expectedS3ContentSHA256(signedRoot map[string]interface{}) ([]byte, error) {
	signable := selectKeys(signedRoot, SignableRootFields)
	valueBytes, err := CanonicalJSONBytes(signable)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(valueBytes)
	return sum[:], nil
}

// VerifyS3Anchor validates the s3 anchor in anchorRefs: unlike immudb (and
// the retired rekor tier), this binding needs no out-of-band signing key --
// content_sha256 is a pure function of this bundle's own signed_root, so a
// present binding is always checked, regardless of required. required only
// changes how an absent anchor (or one present without a content_sha256
// field to check) is treated: FAILED rather than SKIPPED, letting an
// auditor who knows an s3 anchor must exist detect a stripped one.
func VerifyS3Anchor(anchorRefs map[string]interface{}, required bool, signedRoot map[string]interface{}) S3Result {
	s3, ok := getMap(anchorRefs, "s3")
	if !ok {
		if required {
			return S3Result{AnchorFailed, "required s3 anchor is absent from bundle (--require-anchor s3)"}
		}
		return S3Result{AnchorSkipped, "no s3 anchor in bundle"}
	}
	contentSHA256B64, hasContent := getString(s3, "content_sha256")
	if !hasContent {
		if required {
			return S3Result{AnchorFailed, "required s3 anchor present but content_sha256 is missing (--require-anchor s3); cannot validate"}
		}
		return S3Result{AnchorSkipped, "s3 anchor present but content_sha256 is missing; binding cannot be checked"}
	}
	actual, err := b64Decode(contentSHA256B64)
	if err != nil {
		return S3Result{AnchorFailed, "s3 anchor content_sha256 is not valid base64"}
	}
	expected, err := expectedS3ContentSHA256(signedRoot)
	if err != nil {
		return S3Result{AnchorFailed, fmt.Sprintf("cannot verify s3 anchor binding: %v", err)}
	}
	if !bytes.Equal(expected, actual) {
		return S3Result{AnchorFailed, "s3 object content_sha256 does not match this bundle's signed_root (anchor may belong to a different bundle)"}
	}
	return S3Result{AnchorVerified, "s3 content_sha256 binding verified"}
}
