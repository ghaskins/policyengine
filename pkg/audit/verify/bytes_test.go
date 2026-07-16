//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestB64DecodeAcceptsEitherAlphabet(t *testing.T) {
	t.Parallel()

	want := []byte{0xfb, 0xff, 0xbf}

	std, err := b64Decode("+/+/")
	require.NoError(t, err)
	assert.Equal(t, want, std)

	url, err := b64Decode("-_-_")
	require.NoError(t, err)
	assert.Equal(t, want, url)
}

func TestB64DecodeRejectsMixedAlphabet(t *testing.T) {
	t.Parallel()

	_, err := b64Decode("ab-c+d_e/f")
	assert.Error(t, err, "a string mixing standard (+/) and URL-safe (-_) characters must be rejected, not silently normalized")
}

func TestB64DecodeRejectsOverlongPadding(t *testing.T) {
	t.Parallel()

	assert.False(t, b64CharsRe.MatchString("QQ==="), "padding run longer than 2 must not match b64CharsRe")
	assert.True(t, b64CharsRe.MatchString("QQ=="))

	// Also assert against the function's actual contract, not just the
	// whitebox regex: a future refactor that stops routing through
	// b64CharsRe must still reject this input.
	_, err := b64Decode("QQ===")
	assert.Error(t, err)
}

func TestB64DecodeEmptyInput(t *testing.T) {
	t.Parallel()

	_, err := b64Decode("")
	assert.Error(t, err)
}
