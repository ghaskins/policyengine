//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalJSONBytesSortsKeysAndOmitsWhitespace(t *testing.T) {
	t.Parallel()

	v := normalizeJSON(t, map[string]interface{}{
		"zebra": 1,
		"alpha": 2,
		"nested": map[string]interface{}{
			"z": true,
			"a": false,
		},
	})
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, `{"alpha":2,"nested":{"a":false,"z":true},"zebra":1}`, string(out))
}

func TestCanonicalJSONBytesArrayOrderPreserved(t *testing.T) {
	t.Parallel()

	v := normalizeJSON(t, map[string]interface{}{"list": []interface{}{3, 1, 2}})
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, `{"list":[3,1,2]}`, string(out))
}

func TestCanonicalJSONBytesNullValuePreserved(t *testing.T) {
	t.Parallel()

	v := normalizeJSON(t, map[string]interface{}{"prev_root_id": nil})
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, `{"prev_root_id":null}`, string(out))
}

func TestCanonicalJSONBytesEscapesNonASCII(t *testing.T) {
	t.Parallel()

	// Matches Python's json.dumps(..., ensure_ascii=True): non-ASCII chars
	// are escaped as lowercase \uXXXX, never emitted as raw UTF-8.
	v := normalizeJSON(t, map[string]interface{}{"k": "café"})
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, "{\"k\":\"caf\\u00e9\"}", string(out))
}

// TestCanonicalJSONBytesLeavesDELRaw is the regression for i-7j0j: U+007F
// (DEL) must be left RAW, matching the notary's actual Jackson-based signer
// (notary/canonical.clj), NOT escaped per Python's json.dumps -- Jackson's
// ESCAPE_NON_ASCII feature only covers code points >= 0x80, and its base
// 0-127 escape table never assigns index 127 (confirmed by decompiling
// CharTypes.sOutputEscapes128), so the real signer never escapes DEL.
// Matching the signer -- not idealized Python parity -- is what the
// verifier must do, or a legitimately-signed field containing a literal
// DEL byte would spuriously fail verification.
func TestCanonicalJSONBytesLeavesDELRaw(t *testing.T) {
	t.Parallel()

	v := normalizeJSON(t, map[string]interface{}{"k": "a\x7fb"})
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, "{\"k\":\"a\x7fb\"}", string(out))
}

// TestCanonicalJSONBytesLeavesTildeRaw confirms U+007E ('~'), immediately
// below DEL, also stays unescaped (sanity check on the 0x7f/0x80 boundary).
func TestCanonicalJSONBytesLeavesTildeRaw(t *testing.T) {
	t.Parallel()

	v := normalizeJSON(t, map[string]interface{}{"k": "a~b"})
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, "{\"k\":\"a~b\"}", string(out))
}

func TestCanonicalJSONBytesAstralPlaneSurrogatePair(t *testing.T) {
	t.Parallel()

	// U+1F600 (grinning face) must be emitted as a UTF-16 surrogate pair,
	// matching both Python's ensure_ascii=True and the Clojure reference's
	// Jackson-based encoder.
	v := normalizeJSON(t, map[string]interface{}{"k": "\U0001F600"})
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, "{\"k\":\"\\ud83d\\ude00\"}", string(out))
}

// TestCanonicalJSONBytesRejectsInvalidUTF8 is the regression for the
// canonicalization-ambiguity finding in the code review of ac82395: ranging
// over a Go string with `for _, r := range s` silently substitutes U+FFFD
// for each invalid UTF-8 byte, so a malformed byte sequence and a genuine
// U+FFFD would otherwise canonicalize to identical bytes -- a value that
// cannot be reproduced byte-for-byte against the actual signer must fail
// loudly, not silently match a different value.
func TestCanonicalJSONBytesRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()

	v := map[string]interface{}{"k": "a\xffb"} // 0xff is never valid UTF-8
	_, err := CanonicalJSONBytes(v)
	assert.Error(t, err)
}

// TestCanonicalJSONBytesRejectsInvalidUTF8Key covers the same check on a map
// key, not just a value.
func TestCanonicalJSONBytesRejectsInvalidUTF8Key(t *testing.T) {
	t.Parallel()

	v := map[string]interface{}{"a\xffb": 1}
	_, err := CanonicalJSONBytes(v)
	assert.Error(t, err)
}

// TestCanonicalJSONBytesAcceptsGenuineReplacementCharacter confirms the
// well-formed-UTF-8 check does not reject a legitimately-encoded U+FFFD --
// only actually malformed byte sequences must be rejected.
func TestCanonicalJSONBytesAcceptsGenuineReplacementCharacter(t *testing.T) {
	t.Parallel()

	v := map[string]interface{}{"k": "a�b"}
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, "{\"k\":\"a\\ufffdb\"}", string(out))
}

func TestCanonicalJSONBytesRejectsNonIntegralNumbers(t *testing.T) {
	t.Parallel()

	v := map[string]interface{}{"x": json.Number("1.5")}
	_, err := CanonicalJSONBytes(v)
	assert.Error(t, err)
}

func TestCanonicalJSONBytesRejectsBeyondSignedInt64Range(t *testing.T) {
	t.Parallel()

	// The Clojure reference's assert-canonical-number! only permits
	// Long/Integer/Short/Byte (signed int64 range); a value beyond
	// int64::MAX must be rejected here too, not silently accepted via a
	// wider uint64 range that the Clojure implementation would reject.
	v := map[string]interface{}{"x": json.Number("18446744073709551615")} // uint64::MAX
	_, err := CanonicalJSONBytes(v)
	assert.Error(t, err)
}

func TestCanonicalJSONBytesRejectsUnsupportedType(t *testing.T) {
	t.Parallel()

	_, err := CanonicalJSONBytes(map[string]interface{}{"x": 3.14})
	assert.Error(t, err, "raw float64 (as opposed to json.Number) must be rejected, not silently coerced")
}

func TestCanonicalJSONBytesLargeIntegerPreservedExactly(t *testing.T) {
	t.Parallel()

	// A value beyond float64's 53-bit exact-integer range must round-trip
	// byte-for-byte -- this is the whole reason DecodeBundle uses
	// json.Number instead of the default float64.
	const big = "9223372036854775807"
	v := map[string]interface{}{"timestamp_ms": json.Number(big)}
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, `{"timestamp_ms":9223372036854775807}`, string(out))
}

func TestCanonicalJSONBytesNegativeIntegerPreserved(t *testing.T) {
	t.Parallel()

	v := map[string]interface{}{"x": json.Number("-42")}
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, `{"x":-42}`, string(out))
}

func TestCanonicalJSONBytesNegativeZeroNormalized(t *testing.T) {
	t.Parallel()

	// "-0" is valid per RFC 8259 grammar and survives Go's json.Decoder, but
	// Python's json.dumps(json.loads("-0")) == "0" -- the literal must be
	// normalized to its parsed value, not echoed verbatim, to preserve the
	// byte-identical-to-Python contract.
	v := map[string]interface{}{"x": json.Number("-0")}
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, `{"x":0}`, string(out))
}

func TestCanonicalJSONBytesInt64MinPreservedExactly(t *testing.T) {
	t.Parallel()

	// The signed int64 boundary opposite TestCanonicalJSONBytesLargeIntegerPreservedExactly
	// (int64::MAX): math.MinInt64 must round-trip exactly, and must not be
	// rejected by writeCanonicalNumber's ParseInt call (which would happen if
	// the parser only handled the positive boundary correctly).
	const min = "-9223372036854775808"
	v := map[string]interface{}{"x": json.Number(min)}
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, `{"x":-9223372036854775808}`, string(out))
}

func TestCanonicalJSONBytesBeyondInt64MinRejected(t *testing.T) {
	t.Parallel()

	// One below int64::MIN must be rejected, mirroring
	// TestCanonicalJSONBytesRejectsBeyondSignedInt64Range's positive-side
	// coverage of the same signed-int64-only contract.
	v := map[string]interface{}{"x": json.Number("-9223372036854775809")}
	_, err := CanonicalJSONBytes(v)
	assert.Error(t, err)
}

func TestCanonicalJSONBytesEmptyMapAndArray(t *testing.T) {
	t.Parallel()

	v := normalizeJSON(t, map[string]interface{}{
		"empty_map":   map[string]interface{}{},
		"empty_array": []interface{}{},
	})
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, `{"empty_array":[],"empty_map":{}}`, string(out))
}

func TestCanonicalJSONBytesNonASCIIKeySortedAndEscaped(t *testing.T) {
	t.Parallel()

	// Map keys are recursively sorted (per writeCanonicalMap's doc comment)
	// by Go's byte-wise string comparison, which is code-point order for
	// valid UTF-8 -- this must hold for the KEY itself, not just string
	// values, and the key must be \uXXXX-escaped identically to a value.
	v := normalizeJSON(t, map[string]interface{}{"café": 1, "a": 2, "z": 3})
	out, err := CanonicalJSONBytes(v)
	require.NoError(t, err)
	assert.Equal(t, "{\"a\":2,\"caf\\u00e9\":1,\"z\":3}", string(out))
}
