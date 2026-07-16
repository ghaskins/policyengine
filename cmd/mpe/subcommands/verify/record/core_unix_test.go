//go:build !windows

//
//  Copyright © Manetu Inc. All rights reserved.
//

package record

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRun_UnboundedFifoInputDoesNotHang is the regression for the file-read
// memory-cap bypass found in the code review of ac82395: loadBundle's
// maxInputBytes cap was enforced by comparing len(data) *after*
// os.ReadFile had already read the entire file, so a file input had none of
// the protection stdin already got from io.LimitReader. Against a FIFO (or
// any input that never sends EOF -- the realistic shape of "an adversarial
// multi-gigabyte input" the cap's own doc comment warns about), the old
// os.ReadFile-based path would block forever waiting for EOF instead of
// stopping at the cap. This test writes more than maxInputBytes+1 bytes into
// a FIFO without ever closing the writer end, and asserts loadBundle returns
// (rejecting the oversized input) well before the writer finishes -- proving
// the read is bounded by the cap, not by EOF.
func TestRun_UnboundedFifoInputDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "bundle.fifo")
	require.NoError(t, syscall.Mkfifo(fifoPath, 0o600))

	oldMax := maxInputBytes
	maxInputBytes = 1024
	defer func() { maxInputBytes = oldMax }()

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0o600) // #nosec G304 -- test writes to its own tempdir fixture
		if err != nil {
			return
		}
		defer f.Close() //nolint:errcheck // best-effort cleanup in test writer goroutine
		chunk := make([]byte, 4096)
		for i := range chunk {
			chunk[i] = 'a'
		}
		// Keep writing well past the cap; never close early. A FIFO writer
		// blocks once the kernel pipe buffer fills and the reader has
		// stopped reading, so this goroutine will still be blocked in
		// Write when the assertions below run -- exactly the "never sends
		// EOF" condition the fix must not hang on.
		for j := 0; j < 1<<20; j++ { // far more than maxInputBytes could ever accept
			if _, err := f.Write(chunk); err != nil {
				return
			}
		}
	}()

	resultCh := make(chan error, 1)
	go func() {
		_, err := loadBundle(fifoPath)
		resultCh <- err
	}()

	select {
	case err := <-resultCh:
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds")
	case <-time.After(10 * time.Second):
		t.Fatal("loadBundle did not return within 10s: file read is not bounded by maxInputBytes")
	}

	// The writer goroutine is intentionally left running (writing into a
	// FIFO with a closed reader will eventually error out on its own); the
	// test does not wait on writerDone since that would reintroduce the
	// unbounded-wait this test exists to rule out.
	_ = writerDone
}
