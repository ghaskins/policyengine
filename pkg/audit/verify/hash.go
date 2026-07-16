//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import "crypto/sha256"

// LeafHash returns the SHA-256 digest of raw protobuf record bytes -- no
// re-encoding. This is the value a bundle's record.integrity.leaf_hash_b64
// must match.
func LeafHash(recordPB []byte) []byte {
	h := sha256.Sum256(recordPB)
	return h[:]
}
