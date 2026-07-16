//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePublicKeyAndVerifySignatureEd25519(t *testing.T) {
	t.Parallel()

	kp := genEd25519KeyPair(t)
	pemStr := pemEncodePublicKey(t, kp.pub)
	parsed, err := ParsePublicKey(pemStr)
	require.NoError(t, err)

	msg := []byte("attest this")
	sig := kp.sign(msg)
	assert.True(t, VerifySignature(parsed, msg, sig))
	assert.False(t, VerifySignature(parsed, []byte("different message"), sig))
	assert.False(t, VerifySignature(parsed, msg, []byte("not a signature")))
}

func TestParsePublicKeyAndVerifySignatureECDSA(t *testing.T) {
	t.Parallel()

	kp := genECDSAKeyPair(t)
	pemStr := pemEncodePublicKey(t, kp.pub)
	parsed, err := ParsePublicKey(pemStr)
	require.NoError(t, err)

	msg := []byte("attest this")
	sig := kp.sign(msg)
	assert.True(t, VerifySignature(parsed, msg, sig))
	assert.False(t, VerifySignature(parsed, []byte("different message"), sig))
	assert.False(t, VerifySignature(parsed, msg, []byte("not a signature")))
}

func TestParsePublicKeyRejectsGarbage(t *testing.T) {
	t.Parallel()

	_, err := ParsePublicKey("not a pem block")
	assert.Error(t, err)
}

// TestParsePublicKeyRejectsGarbageDERInsidePEM covers the x509 parse-failure
// branch specifically: a syntactically valid PEM armor wrapping bytes that
// are not a valid SubjectPublicKeyInfo DER structure.
func TestParsePublicKeyRejectsGarbageDERInsidePEM(t *testing.T) {
	t.Parallel()

	pemStr := "-----BEGIN PUBLIC KEY-----\n" +
		"bm90IGEgcmVhbCBERVIgc3RydWN0dXJl\n" +
		"-----END PUBLIC KEY-----\n"
	_, err := ParsePublicKey(pemStr)
	assert.Error(t, err)
}

func TestParsePublicKeyRejectsNonP256ECDSACurve(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	pemStr := pemEncodePublicKey(t, &priv.PublicKey)

	_, err = ParsePublicKey(pemStr)
	assert.Error(t, err)
}

// TestParsePublicKeyRejectsUnsupportedKeyType covers keys.go's default: arm
// (ParsePublicKey.40) with a *valid* PKIX key of a type the notary never
// signs with, not just malformed input -- RSA public keys parse successfully
// under x509.ParsePKIXPublicKey but must still be rejected here.
func TestParsePublicKeyRejectsUnsupportedKeyType(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemStr := pemEncodePublicKey(t, &priv.PublicKey)

	_, err = ParsePublicKey(pemStr)
	assert.Error(t, err)
}

func TestVerifySignatureRejectsUnsupportedKeyType(t *testing.T) {
	t.Parallel()

	assert.False(t, VerifySignature("not a key", []byte("data"), []byte("sig")))
}
