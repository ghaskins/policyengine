//
//  Copyright © Manetu Inc. All rights reserved.
//

package record

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	auditverify "github.com/manetu/policyengine/pkg/audit/verify"
	"github.com/stretchr/testify/require"
)

// TestRun_MaliciousRecordIDCannotSpoofTerminal is the regression for i-33dl:
// per this tool's own threat model, a bundle is exactly what an adversary
// controls, and record_id is read straight from the bundle. A record_id
// carrying ANSI/terminal escape sequences (here, a cursor-up + line-clear
// sequence followed by a forged "RESULT: OK" line) must not reach the
// terminal verbatim -- it could otherwise overwrite or hide prior output and
// spoof a fake success line for a human eyeballing the terminal, even though
// the tool's real exit code (driven by record-b's genuine tamper) stays
// correctly non-zero.
func TestRun_MaliciousRecordIDCannotSpoofTerminal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleJSON, pubPEM, _, _ := buildSetBundleTwoRoots(t)

	var bundle map[string]interface{}
	require.NoError(t, json.Unmarshal(bundleJSON, &bundle))
	records := bundle["records"].([]interface{})

	recA := records[0].(map[string]interface{})
	const spoofSeq = "\x1b[2K\x1b[1A\rRESULT: OK (exit 0)"
	recA["record_id"] = "rec-a" + spoofSeq

	recB := records[1].(map[string]interface{})
	recordB := recB["record"].(map[string]interface{})
	recordB["record_pb_b64"] = b64([]byte("tampered-record!!"))

	tampered, err := json.Marshal(bundle)
	require.NoError(t, err)

	bundlePath := writeTempFile(t, dir, "bundle.json", tampered)
	keyPath := writeTempFile(t, dir, "key.pem", []byte(pubPEM))

	code, stdout, _ := runCmd(t, []string{"--bundle", bundlePath, "--public-key", keyPath})
	require.Equal(t, 1, code, "record-b's genuine tamper must still drive the real (failing) exit code")

	require.NotContains(t, stdout, "\x1b", "raw ANSI escape byte must never reach stdout")
	require.NotContains(t, stdout, "\r", "raw carriage return must never reach stdout")

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	require.Contains(t, lines, "RESULT: FAILED (exit 1)",
		"the genuine verdict line must be the real (failing) one")
	for _, line := range lines {
		require.NotEqual(t, "RESULT: OK (exit 0)", line,
			"the injected record_id must not render as its own standalone spoofed verdict line")
	}

	require.Contains(t, stdout, "Record rec-a[2K[1ARESULT: OK (exit 0): VERIFIED",
		"the neutralized record_id (escape/CR stripped, printable text retained) should still render inertly on its own record line")
}

// TestFormatRecordLine_RootHashHintTruncatesOnRuneBoundary is the regression
// for the root_hash_b64 half of i-33dl: the hint byte-sliced root_hash_b64
// before it was ever validated as base64, so a multi-byte UTF-8 sequence in
// that bundle field could be cut mid-rune and emit invalid UTF-8. The fix
// truncates on rune boundaries instead.
func TestFormatRecordLine_RootHashHintTruncatesOnRuneBoundary(t *testing.T) {
	t.Parallel()

	// 'A' followed by 15 four-byte emoji runes: a byte-length-12 slice lands
	// inside the third emoji's 4-byte encoding (1 + 2*4 = 9, +4 = 13 > 12),
	// splitting it, while a rune-length-12 slice never does.
	maliciousRootHash := "A" + strings.Repeat("\U0001F600", 15)
	signedRoot := map[string]interface{}{"root_hash_b64": maliciousRootHash}
	rec := auditverify.RecordResult{
		RecordID: "rec-a",
		Status:   auditverify.StatusVerified,
		Detail:   "leaf hash and signature verified",
	}

	line := formatRecordLine(rec, signedRoot)

	require.True(t, utf8.ValidString(line), "rendered line must be valid UTF-8, not cut mid-rune")
	require.Contains(t, line, "root="+truncateRunes(maliciousRootHash, 12)+"…")
}
