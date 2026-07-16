//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CanonicalJSONBytes returns the canonical JSON encoding of v: byte-identical
// to Python's json.dumps(v, sort_keys=True, separators=(',', ':'),
// ensure_ascii=True).
//
// Map keys are recursively sorted at every nesting level; Go's byte-wise
// string comparison equals Unicode code-point order for valid UTF-8, which
// matches Python's str comparison (including astral-plane characters, where
// naive UTF-16-unit comparison would diverge). Non-ASCII characters are
// escaped as lowercase \uXXXX sequences, with astral-plane runes emitted as
// a UTF-16 surrogate pair, matching Python's ensure_ascii=True output
// byte-for-byte. Array element order is preserved, not sorted.
//
// Only nil, bool, string, json.Number, []interface{}, and
// map[string]interface{} values are permitted (the shapes produced by
// decoding JSON with a json.Decoder in UseNumber mode). json.Number values
// must be integral -- non-integral numbers (float, exponent notation) are
// rejected to prevent silently diverging from Python's json.dumps, which
// this package never needs to reproduce for non-integral types.
func CanonicalJSONBytes(v interface{}) ([]byte, error) {
	var buf strings.Builder
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func writeCanonical(buf *strings.Builder, v interface{}) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		return writeCanonicalString(buf, x)
	case json.Number:
		return writeCanonicalNumber(buf, x)
	case map[string]interface{}:
		return writeCanonicalMap(buf, x)
	case []interface{}:
		return writeCanonicalArray(buf, x)
	default:
		return fmt.Errorf("verify: canonical-json: unsupported value type %T", v)
	}
	return nil
}

func writeCanonicalNumber(buf *strings.Builder, n json.Number) error {
	s := string(n)
	if strings.ContainsAny(s, ".eE") {
		return fmt.Errorf("verify: canonical-json: non-integral numeric type not permitted: %s", s)
	}
	// Signed int64 range only, matching the Clojure reference's
	// assert-canonical-number! (Long/Integer/Short/Byte; BigInteger is
	// rejected). Accepting the wider uint64 range here would silently
	// diverge from what the Clojure implementation accepts for the same
	// canonical-JSON payload.
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("verify: canonical-json: invalid integer literal: %s", s)
	}
	buf.WriteString(strconv.FormatInt(i, 10))
	return nil
}

func writeCanonicalMap(buf *strings.Builder, m map[string]interface{}) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonicalString(buf, k); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := writeCanonical(buf, m[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func writeCanonicalArray(buf *strings.Builder, arr []interface{}) error {
	buf.WriteByte('[')
	for i, e := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonical(buf, e); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

// writeCanonicalString escapes s exactly as Python's
// json.dumps(..., ensure_ascii=True) does: standard JSON control-character/
// quote/backslash escaping, plus every non-ASCII rune emitted as \uXXXX
// (lowercase hex; astral-plane runes as a UTF-16 surrogate pair).
//
// s must be well-formed UTF-8 -- returns an error otherwise, rather than
// silently substituting U+FFFD for each invalid byte the way `range` over a
// Go string does. Without this check, two distinct signed-field values (an
// invalid byte sequence vs. a genuine U+FFFD) could canonicalize to
// identical bytes, and a value that cannot be reproduced byte-for-byte
// against the actual signer would silently match a different value instead
// of failing loudly. Note this only catches malformed bytes reaching this
// function directly: a lone UTF-16 surrogate escape (e.g. "\uD800") in the
// original bundle JSON is already collapsed to a valid-UTF-8-encoded U+FFFD
// by encoding/json's decoder before DecodeBundle's output ever reaches
// here, and recovering that distinction would require a custom JSON string
// decoder -- out of scope for this defense-in-depth check.
func writeCanonicalString(buf *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("verify: canonical-json: string is not well-formed UTF-8")
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(buf, `\u%04x`, r)
			case r < 0x80:
				// U+007F (DEL) is intentionally left raw here, NOT escaped,
				// even though Python's json.dumps(ensure_ascii=True) does
				// escape it (verified directly against CPython). The signer
				// this verifier must byte-match is the notary's Jackson-based
				// canonical-json-str (notary/canonical.clj), which configures
				// JsonWriteFeature.ESCAPE_NON_ASCII -- and Jackson's own
				// CharTypes.sOutputEscapes128 table (decompiled and
				// confirmed) never assigns index 127, so Jackson leaves DEL
				// raw regardless of that feature (ESCAPE_NON_ASCII only
				// affects code points >= 128). Matching the actual signer is
				// the correctness invariant that matters, not idealized
				// Python parity -- escaping DEL here would make this verifier
				// reject a legitimately-signed field containing a literal DEL
				// byte. See i-7j0j.
				buf.WriteRune(r)
			case r <= 0xFFFF:
				fmt.Fprintf(buf, `\u%04x`, r)
			default:
				r -= 0x10000
				hi := 0xD800 + (r >> 10)
				lo := 0xDC00 + (r & 0x3FF)
				fmt.Fprintf(buf, `\u%04x\u%04x`, hi, lo)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}
