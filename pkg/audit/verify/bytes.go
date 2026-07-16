//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// concatBytes concatenates one or more byte slices into a single new slice.
// Domain-separation is the caller's responsibility: prefix a type
// discriminator before calling concatBytes to prevent second-preimage
// collisions across hash domains.
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

// longToBEBytes encodes n as 8 big-endian bytes -- the raw two's-complement
// bit pattern, matching Java/Clojure's long->bytes. The conversion itself is
// a lossless reinterpretation of the bit pattern, never a range check, so it
// does not itself enforce non-negativity. Callers that feed in
// externally-controlled values -- e.g. immudb's tx_id/tx_bl_tx_id, read
// straight from the bundle -- are responsible for rejecting negative input
// before calling; see ComputeImmudbALH and buildImmudbStatePayload.
func longToBEBytes(n int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(n)) // #nosec G115 -- lossless bit-pattern reinterpretation, not a range-narrowing conversion
	return b
}

// intToBEBytes encodes n as 4 big-endian bytes. n must be in [0, 0xFFFFFFFF].
func intToBEBytes(n int64) ([]byte, error) {
	if n < 0 || n > 0xFFFFFFFF {
		return nil, fmt.Errorf("verify: int->be-bytes: value out of uint32 range: %d", n)
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(n))
	return b, nil
}

// shortToBEBytes encodes n as 2 big-endian bytes. n must be in [0, 0xFFFF].
func shortToBEBytes(n int64) ([]byte, error) {
	if n < 0 || n > 0xFFFF {
		return nil, fmt.Errorf("verify: short->be-bytes: value out of uint16 range: %d", n)
	}
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n))
	return b, nil
}

var b64CharsRe = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

// b64Decode decodes a base64 string, accepting either the standard (+/) or
// the URL-safe (-_) alphabet, with or without padding. It is deliberately
// lenient across calls: bundle fields mix base64url-no-padding
// (record_pb_b64, leaf_hash_b64, ...) with the one opaque standard-base64
// (padded) blob, anchor_refs.s3.content_sha256 -- see
// docs/docs/reference/verification-bundle-schema.md "Base64 Encoding Convention".
// But within a single string the two alphabets must not be mixed, since
// that isn't valid base64 of either variant and silently normalizing it
// would misrepresent the input rather than reject it. Every decoded value
// is subsequently hash- or signature-checked, so a string that isn't
// canonical base64 of either variant simply fails verification downstream
// rather than being silently misinterpreted.
func b64Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("verify: b64Decode: empty input")
	}
	hasStd := strings.ContainsAny(s, "+/")
	hasURL := strings.ContainsAny(s, "-_")
	if hasStd && hasURL {
		return nil, errors.New("verify: b64Decode: mixed standard and URL-safe base64 alphabets")
	}
	normalized := strings.NewReplacer("-", "+", "_", "/").Replace(s)
	if rem := len(normalized) % 4; rem != 0 {
		normalized += strings.Repeat("=", 4-rem)
	}
	if !b64CharsRe.MatchString(normalized) {
		return nil, errors.New("verify: b64Decode: invalid base64 characters")
	}
	return base64.StdEncoding.DecodeString(normalized)
}

// b64urlEncode encodes b as base64url with no padding -- the convention
// this package's own leaf_hash_b64/record_pb_b64/etc. fields use (see
// docs/docs/reference/verification-bundle-schema.md "Base64 Encoding
// Convention"). Used internally to re-derive content_hash_b64 from a raw
// leaf-hash byte slice for [PositionedLeafHash].
func b64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
