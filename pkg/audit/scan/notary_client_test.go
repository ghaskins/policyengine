//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNotaryClientLeaves(t *testing.T) {
	ns := newFakeNotaryServer(t)
	ns.leaves["root-1"] = []LeafRow{
		{ID: "a", Seq: 0, LeafIndex: 0, LeafHashB64: "aaaa"},
		{ID: "b", Seq: 1, LeafIndex: 1, LeafHashB64: "bbbb"},
	}
	rows, err := ns.client().Leaves(context.Background(), "root-1")
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "a", rows[0].ID)
	assert.Equal(t, int64(1), rows[1].LeafIndex)
}

func TestNotaryClientLeavesEmptyRoot(t *testing.T) {
	ns := newFakeNotaryServer(t)
	rows, err := ns.client().Leaves(context.Background(), "no-such-root")
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestNotaryClientRecordExistenceFoundAndMissing(t *testing.T) {
	ns := newFakeNotaryServer(t)
	authAbsent := true
	ns.existence["found-id"] = RecordExistenceRow{ID: "found-id", Found: true, LeafHashB64: "lh", SignatureB64: "sig"}
	ns.existence["missing-id"] = RecordExistenceRow{ID: "missing-id", Found: false, AuthorizedAbsent: &authAbsent}
	ns.existence["unknown-id"] = RecordExistenceRow{ID: "unknown-id", Found: false, AuthorizedAbsent: nil}

	rows, err := ns.client().RecordExistence(context.Background(), []string{"found-id", "missing-id", "unknown-id"})
	require.NoError(t, err)
	require.Len(t, rows, 3)

	byID := map[string]RecordExistenceRow{}
	for _, r := range rows {
		byID[r.ID] = r
	}
	assert.True(t, byID["found-id"].Found)
	assert.Equal(t, "lh", byID["found-id"].LeafHashB64)

	assert.False(t, byID["missing-id"].Found)
	require.NotNil(t, byID["missing-id"].AuthorizedAbsent)
	assert.True(t, *byID["missing-id"].AuthorizedAbsent)

	assert.False(t, byID["unknown-id"].Found)
	assert.Nil(t, byID["unknown-id"].AuthorizedAbsent, "an undetermined authorization must decode as nil, never default to true or false")
}

func TestNotaryClientRecordExistenceEmptyIDsIsNoop(t *testing.T) {
	ns := newFakeNotaryServer(t)
	rows, err := ns.client().RecordExistence(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, rows)
}
