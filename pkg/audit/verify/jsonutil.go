//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// DecodeBundle parses bundle JSON into a generic map, preserving exact
// numeric literals as json.Number rather than lossy float64. This is
// required so that re-serializing a signed subset of the bundle (Step 4,
// SignableRootFields) via CanonicalJSONBytes reproduces byte-identical JSON
// to what the notary actually signed, even for 64-bit millisecond
// timestamps that exceed float64's 53-bit exact-integer range.
func DecodeBundle(data []byte) (map[string]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("verify: failed to decode bundle JSON: %w", err)
	}
	return m, nil
}

// getMap returns m[key] as a map, and whether it was present and
// map-shaped. A present-but-null value is treated as absent.
func getMap(m map[string]interface{}, key string) (map[string]interface{}, bool) {
	if m == nil {
		return nil, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil, false
	}
	mm, ok := v.(map[string]interface{})
	return mm, ok
}

// getString returns m[key] as a string, and whether it was present and
// string-shaped. A present-but-null value is treated as absent.
func getString(m map[string]interface{}, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// getSlice returns m[key] as a slice, and whether it was present and
// array-shaped. A present-but-null value is treated as absent.
func getSlice(m map[string]interface{}, key string) ([]interface{}, bool) {
	if m == nil {
		return nil, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil, false
	}
	s, ok := v.([]interface{})
	return s, ok
}

// getInt64 returns m[key] as an int64 decoded from a JSON number, and
// whether it was present and numeric. A present-but-null value is treated
// as absent. Only json.Number is handled (not float64): every map passed
// here originates from DecodeBundle, which decodes numbers via
// json.Decoder.UseNumber().
func getInt64(m map[string]interface{}, key string) (int64, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	if n, ok := v.(json.Number); ok {
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	}
	return 0, false
}

// getInt64Loose is getInt64, but also accepts a JSON string of digits --
// grpc-gateway encodes int64/uint64 fields as strings to avoid JS precision
// loss, so some anchor_refs.immudb fields (tx_id, tx_ts, ...) may arrive
// either way.
func getInt64Loose(m map[string]interface{}, key string) (int64, bool) {
	if i, ok := getInt64(m, key); ok {
		return i, true
	}
	if m == nil {
		return 0, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	if s, ok := v.(string); ok {
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, false
		}
		return i, true
	}
	return 0, false
}
