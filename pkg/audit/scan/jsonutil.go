//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"

	"github.com/manetu/policyengine/pkg/audit/verify"
)

// num returns a json.Number for v, so hand-built maps interoperate with
// pkg/audit/verify's exported helpers (CanonicalJSONBytes, VerifyRootSignature,
// VerifyImmudbAnchor, ...), which only accept json.Number for numeric values --
// exactly what a real json.Decoder(UseNumber()) would have produced. A raw Go
// int64 would fail verify's canonical-JSON encoder ("unsupported value type").
func num(v int64) json.Number {
	return json.Number(strconv.FormatInt(v, 10))
}

// decodeJSONMap parses data into a map[string]interface{} using
// json.Decoder.UseNumber(), so numeric literals decode as json.Number rather
// than lossy float64 -- required for byte-identical canonical-JSON
// reconstruction of 64-bit fields (notary_ts_from/to, tx_id, ...) and for
// interoperating with pkg/audit/verify's exported functions, which assume
// this exact decoding convention.
func decodeJSONMap(data []byte) (map[string]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

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

func getInt64(m map[string]interface{}, key string) (int64, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func b64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// selectSignableFields projects payload down to verify.SignableRootFields --
// mpe-iam-lite's canonical/signable-root-fields, the single source of truth
// for what a root's signature (and, identically, its immudb entry_hash / S3
// content_sha256 anchor bindings) actually covers.
func selectSignableFields(payload map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(verify.SignableRootFields))
	for _, k := range verify.SignableRootFields {
		if v, ok := payload[k]; ok {
			out[k] = v
		}
	}
	return out
}
