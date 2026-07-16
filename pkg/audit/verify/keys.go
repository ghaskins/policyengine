//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ParsePublicKey parses a PEM-encoded SubjectPublicKeyInfo block into an
// Ed25519 or ECDSA P-256 public key, the two algorithms the notary signs
// with (see docs/docs/reference/verification-bundle-schema.md "Cryptographic
// Algorithms").
func ParsePublicKey(pemStr string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("verify: no PEM block found in public key input")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("verify: failed to parse public key: %w", err)
	}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return pub, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("verify: unsupported ECDSA curve %s, only P-256 is supported", k.Curve.Params().Name)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("verify: unsupported public key type %T", pub)
	}
}

// VerifySignature verifies sig over data using pubKey, an Ed25519 or ECDSA
// P-256 key as returned by [ParsePublicKey]. ECDSA verification hashes data
// with SHA-256 first (docs' "ECDSA-P256-SHA256"); Ed25519 is applied to data
// directly. Returns false -- never an error -- on any failure, mirroring the
// Clojure reference's fail-closed verify-sig, which treats a malformed
// signature the same as an invalid one.
func VerifySignature(pubKey interface{}, data, sig []byte) bool {
	switch k := pubKey.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(k, data, sig)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(data)
		return ecdsa.VerifyASN1(k, digest[:], sig)
	default:
		return false
	}
}
