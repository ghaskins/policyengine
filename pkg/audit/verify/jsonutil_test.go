//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetMap(t *testing.T) {
	t.Parallel()

	t.Run("nil parent", func(t *testing.T) {
		t.Parallel()
		v, ok := getMap(nil, "key")
		assert.False(t, ok)
		assert.Nil(t, v)
	})

	t.Run("missing key", func(t *testing.T) {
		t.Parallel()
		v, ok := getMap(map[string]interface{}{}, "key")
		assert.False(t, ok)
		assert.Nil(t, v)
	})

	t.Run("present but null", func(t *testing.T) {
		t.Parallel()
		v, ok := getMap(map[string]interface{}{"key": nil}, "key")
		assert.False(t, ok)
		assert.Nil(t, v)
	})

	t.Run("wrong type", func(t *testing.T) {
		t.Parallel()
		v, ok := getMap(map[string]interface{}{"key": "not-a-map"}, "key")
		assert.False(t, ok)
		assert.Nil(t, v)
	})

	t.Run("well formed", func(t *testing.T) {
		t.Parallel()
		want := map[string]interface{}{"nested": "value"}
		v, ok := getMap(map[string]interface{}{"key": want}, "key")
		assert.True(t, ok)
		assert.Equal(t, want, v)
	})
}

func TestGetString(t *testing.T) {
	t.Parallel()

	t.Run("nil parent", func(t *testing.T) {
		t.Parallel()
		v, ok := getString(nil, "key")
		assert.False(t, ok)
		assert.Empty(t, v)
	})

	t.Run("missing key", func(t *testing.T) {
		t.Parallel()
		v, ok := getString(map[string]interface{}{}, "key")
		assert.False(t, ok)
		assert.Empty(t, v)
	})

	t.Run("present but null", func(t *testing.T) {
		t.Parallel()
		v, ok := getString(map[string]interface{}{"key": nil}, "key")
		assert.False(t, ok)
		assert.Empty(t, v)
	})

	t.Run("wrong type", func(t *testing.T) {
		t.Parallel()
		v, ok := getString(map[string]interface{}{"key": 42}, "key")
		assert.False(t, ok)
		assert.Empty(t, v)
	})

	t.Run("well formed", func(t *testing.T) {
		t.Parallel()
		v, ok := getString(map[string]interface{}{"key": "value"}, "key")
		assert.True(t, ok)
		assert.Equal(t, "value", v)
	})
}

func TestGetSlice(t *testing.T) {
	t.Parallel()

	t.Run("nil parent", func(t *testing.T) {
		t.Parallel()
		v, ok := getSlice(nil, "key")
		assert.False(t, ok)
		assert.Nil(t, v)
	})

	t.Run("missing key", func(t *testing.T) {
		t.Parallel()
		v, ok := getSlice(map[string]interface{}{}, "key")
		assert.False(t, ok)
		assert.Nil(t, v)
	})

	t.Run("present but null", func(t *testing.T) {
		t.Parallel()
		v, ok := getSlice(map[string]interface{}{"key": nil}, "key")
		assert.False(t, ok)
		assert.Nil(t, v)
	})

	t.Run("wrong type object instead of array", func(t *testing.T) {
		t.Parallel()
		v, ok := getSlice(map[string]interface{}{"key": map[string]interface{}{"a": 1}}, "key")
		assert.False(t, ok)
		assert.Nil(t, v)
	})

	t.Run("well formed", func(t *testing.T) {
		t.Parallel()
		want := []interface{}{"a", "b"}
		v, ok := getSlice(map[string]interface{}{"key": want}, "key")
		assert.True(t, ok)
		assert.Equal(t, want, v)
	})
}

func TestGetInt64(t *testing.T) {
	t.Parallel()

	t.Run("nil parent", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64(nil, "key")
		assert.False(t, ok)
		assert.Zero(t, v)
	})

	t.Run("missing key", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64(map[string]interface{}{}, "key")
		assert.False(t, ok)
		assert.Zero(t, v)
	})

	t.Run("present but null", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64(map[string]interface{}{"key": nil}, "key")
		assert.False(t, ok)
		assert.Zero(t, v)
	})

	t.Run("wrong type string", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64(map[string]interface{}{"key": "123"}, "key")
		assert.False(t, ok)
		assert.Zero(t, v)
	})

	t.Run("wrong type float64", func(t *testing.T) {
		t.Parallel()
		// Bundles are always decoded via DecodeBundle's json.Decoder.UseNumber(),
		// so a bare float64 should never occur in practice, but getInt64 must
		// still refuse it rather than silently truncating.
		v, ok := getInt64(map[string]interface{}{"key": float64(123)}, "key")
		assert.False(t, ok)
		assert.Zero(t, v)
	})

	t.Run("non-integer json.Number", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64(map[string]interface{}{"key": json.Number("1.5")}, "key")
		assert.False(t, ok)
		assert.Zero(t, v)
	})

	t.Run("well formed", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64(map[string]interface{}{"key": json.Number("42")}, "key")
		assert.True(t, ok)
		assert.Equal(t, int64(42), v)
	})
}

func TestGetInt64Loose(t *testing.T) {
	t.Parallel()

	t.Run("nil parent", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64Loose(nil, "key")
		assert.False(t, ok)
		assert.Zero(t, v)
	})

	t.Run("missing key", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64Loose(map[string]interface{}{}, "key")
		assert.False(t, ok)
		assert.Zero(t, v)
	})

	t.Run("present but null", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64Loose(map[string]interface{}{"key": nil}, "key")
		assert.False(t, ok)
		assert.Zero(t, v)
	})

	t.Run("wrong type non-numeric string", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64Loose(map[string]interface{}{"key": "not-a-number"}, "key")
		assert.False(t, ok)
		assert.Zero(t, v)
	})

	t.Run("wrong type bool", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64Loose(map[string]interface{}{"key": true}, "key")
		assert.False(t, ok)
		assert.Zero(t, v)
	})

	t.Run("json.Number takes priority", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64Loose(map[string]interface{}{"key": json.Number("42")}, "key")
		assert.True(t, ok)
		assert.Equal(t, int64(42), v)
	})

	t.Run("digit string", func(t *testing.T) {
		t.Parallel()
		v, ok := getInt64Loose(map[string]interface{}{"key": "42"}, "key")
		assert.True(t, ok)
		assert.Equal(t, int64(42), v)
	})
}
