//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

// testKeyPair bundles a generated keypair with a sign closure, so tests can
// exercise both supported signature algorithms identically.
type testKeyPair struct {
	pub  interface{}
	sign func(data []byte) []byte
}

func genEd25519KeyPair(t *testing.T) testKeyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return testKeyPair{
		pub: pub,
		sign: func(data []byte) []byte {
			return ed25519.Sign(priv, data)
		},
	}
}

func genECDSAKeyPair(t *testing.T) testKeyPair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return testKeyPair{
		pub: &priv.PublicKey,
		sign: func(data []byte) []byte {
			digest := sha256.Sum256(data)
			sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
			require.NoError(t, err)
			return sig
		},
	}
}

func pemEncodePublicKey(t *testing.T, pub interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func b64urlEnc(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// invalidBase64 fails b64Decode outright (invalid characters, neither
// standard nor URL-safe alphabet) -- as opposed to a well-formed base64
// string that merely decodes to the wrong bytes. Used across tests to
// exercise decode-error branches distinct from wrong-content tampering.
const invalidBase64 = "$$$notbase64$$$"

// normalizeJSON round-trips v (a plain Go value built with native ints,
// strings, nested maps, etc.) through JSON encode/DecodeBundle, so tests
// build fixtures the same way a real caller would produce one: parsing raw
// bundle JSON. This is what turns integer fields into json.Number and
// avoids type mismatches against the accessor helpers (getInt64, ...),
// which only understand the shapes produced by [DecodeBundle].
func normalizeJSON(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	m, err := DecodeBundle(data)
	require.NoError(t, err)
	return m
}

// signRoot computes the canonical-JSON signature over root's
// SignableRootFields subset and injects root_signature_b64/root_key_id in
// place. root must already be a normalized map (see normalizeJSON).
func signRoot(t *testing.T, kp testKeyPair, root map[string]interface{}) {
	t.Helper()
	signable := selectKeys(root, SignableRootFields)
	payload, err := CanonicalJSONBytes(signable)
	require.NoError(t, err)
	root["root_signature_b64"] = b64urlEnc(kp.sign(payload))
	root["root_key_id"] = "test-key"
}
