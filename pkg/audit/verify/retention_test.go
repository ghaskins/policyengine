//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDuration(t *testing.T) {
	t.Parallel()

	const day = int64(24 * 60 * 60 * 1000)
	cases := []struct {
		in   string
		want int64
	}{
		{"P6M", int64(6 * 30.4375 * float64(day))},
		{"P1Y", 365 * day},
		{"PT1H", 60 * 60 * 1000},
		{"P1Y30D", 365*day + 30*day},
		{"P1W", 7 * day},
	}
	for _, c := range cases {
		got, err := ParseDuration(c.in)
		require.NoError(t, err, c.in)
		assert.Equal(t, c.want, got, c.in)
	}
}

func TestParseDurationRejectsInvalidOrEmpty(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "garbage", "6M", "P"} {
		_, err := ParseDuration(in)
		assert.Errorf(t, err, "expected error for %q", in)
	}
}

// TestParseDurationRejectsOverflowingComponent guards against a component
// too large for int64 (e.g. a corrupted or adversarial retention_policy.P)
// being silently treated as 0 -- which would understate the parsed duration
// and could let an authorized-absent check pass when it should fail closed.
func TestParseDurationRejectsOverflowingComponent(t *testing.T) {
	t.Parallel()

	_, err := ParseDuration("P99999999999999999999Y")
	assert.Error(t, err)
}

// TestParseDurationRejectsOverflowingProduct is the regression for i-1o66:
// a component that fits int64 on its own (unlike the digit-run-too-long
// case above) can still overflow once multiplied by its unit -- must be
// surfaced as an error, not silently wrapped to a garbage value.
func TestParseDurationRejectsOverflowingProduct(t *testing.T) {
	t.Parallel()

	// 9999999999 fits int64 comfortably, but 9999999999 * msY (365 days in
	// ms) overflows int64.
	_, err := ParseDuration("P9999999999Y")
	assert.Error(t, err)
}

// TestParseDurationRejectsOverflowingSum is the regression for i-1o66's
// summation half: the Y and H components each convert to milliseconds
// individually without overflowing (~4.73e18 and ~4.70e18 respectively,
// both under math.MaxInt64 ~9.223e18), but their sum (~9.43e18) does.
func TestParseDurationRejectsOverflowingSum(t *testing.T) {
	t.Parallel()

	_, err := ParseDuration("P150000000YT1306000000000H")
	assert.Error(t, err)
}

func TestAuthorizedFloorRetainAll(t *testing.T) {
	t.Parallel()

	floor, err := AuthorizedFloor(RetentionPolicy{Mode: "retain-all"}, 1_700_000_000_000)
	require.NoError(t, err)
	assert.Equal(t, int64(0), floor)
}

func TestAuthorizedFloorRelative(t *testing.T) {
	t.Parallel()

	now := int64(1_700_000_000_000)
	floor, err := AuthorizedFloor(RetentionPolicy{Mode: "relative", P: "P6M"}, now)
	require.NoError(t, err)
	d, _ := ParseDuration("P6M")
	assert.Equal(t, now-d, floor)
}

func TestAuthorizedFloorUnknownModeErrors(t *testing.T) {
	t.Parallel()

	_, err := AuthorizedFloor(RetentionPolicy{Mode: "bogus"}, 0)
	assert.Error(t, err)

	// A present-but-mode-less policy must error, not silently default to
	// retain-all -- only a wholly ABSENT retention_policy defaults (see
	// retentionFloorOK).
	_, err = AuthorizedFloor(RetentionPolicy{}, 0)
	assert.Error(t, err)
}

func TestRetentionFloorOKAbsentPolicyDefaultsRetainAll(t *testing.T) {
	t.Parallel()

	ok := retentionFloorOK(1, nil, 1_700_000_000_000)
	require.NotNil(t, ok)
	assert.True(t, *ok, "retain-all floor is 0, so any positive timestamp clears it")
}

func TestRetentionFloorOKPresentButModeLessIsParseError(t *testing.T) {
	t.Parallel()

	rp := normalizeJSON(t, map[string]interface{}{"foo": "bar"})
	assert.Nil(t, retentionFloorOK(1_700_000_000_000, rp, 1_700_000_000_000),
		"a present retention_policy with no mode field must fail closed (nil), not silently pass")
}

func TestRetentionFloorOKRelativeAuthorizedAbsent(t *testing.T) {
	t.Parallel()

	now := int64(1_700_000_000_000)
	rp := normalizeJSON(t, map[string]interface{}{"mode": "relative", "P": "P1D"})
	oldTs := now - 2*24*60*60*1000 // 2 days old, floor is 1 day back
	ok := retentionFloorOK(oldTs, rp, now)
	require.NotNil(t, ok)
	assert.False(t, *ok, "a record older than the retention floor is authorized-absent")

	recentTs := now - 60*1000
	ok = retentionFloorOK(recentTs, rp, now)
	require.NotNil(t, ok)
	assert.True(t, *ok)
}
