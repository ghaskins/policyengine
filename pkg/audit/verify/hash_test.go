//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLeafHash(t *testing.T) {
	t.Parallel()

	data := []byte("hello world")
	want := sha256.Sum256(data)
	assert.Equal(t, want[:], LeafHash(data))
}
