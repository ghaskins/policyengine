//
//  Copyright © Manetu Inc. All rights reserved.
//

package record

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	auditverify "github.com/manetu/policyengine/pkg/audit/verify"
)

// mustFprintln writes to w and discards the error. w is stdout/stderr in
// practice, where a write failure is unactionable and would otherwise trip
// errcheck at every call site in this file.
func mustFprintln(w io.Writer, a ...interface{}) {
	_, _ = fmt.Fprintln(w, a...)
}

// mustFprintf is mustFprintln's formatted counterpart.
func mustFprintf(w io.Writer, format string, a ...interface{}) {
	_, _ = fmt.Fprintf(w, format, a...)
}

// sanitizeForDisplay strips control and non-printable runes from an
// untrusted bundle-sourced string before it reaches the terminal. Per this
// tool's threat model, bundle content such as record_id is exactly what an
// adversary controls; without this, a crafted value carrying ANSI/terminal
// escape sequences could rewrite or hide prior output on an operator's
// screen (see i-33dl). Invalid UTF-8 decodes to the harmless replacement
// rune rather than being dropped, so truncation never needs to special-case
// malformed input.
func sanitizeForDisplay(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// truncateRunes returns the first n runes of s, decoding as UTF-8 so a
// multi-byte rune is never split -- unlike a raw byte slice, which can cut a
// bundle-controlled string (e.g. root_hash_b64, not yet validated as base64
// at display time) mid-rune and emit invalid UTF-8.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// statusLabel renders an IntegrityStatus the way the reference Clojure CLI
// does (upper-cased, hyphenated).
func statusLabel(status auditverify.IntegrityStatus) string {
	switch status {
	case auditverify.StatusVerified:
		return "VERIFIED"
	case auditverify.StatusTampered:
		return "TAMPERED"
	case auditverify.StatusUnverifiedNotSealed:
		return "UNVERIFIED-NOT-SEALED"
	default:
		return string(status)
	}
}

// formatRecordLine renders one record's result line, matching the reference
// CLI's "Record <id>: <STATUS> (<detail>; merkle=OK, root=<prefix>…)"
// format.
func formatRecordLine(rec auditverify.RecordResult, signedRoot map[string]interface{}) string {
	var hints []string
	if rec.MerkleOK != nil {
		if *rec.MerkleOK {
			hints = append(hints, "merkle=OK")
		} else {
			hints = append(hints, "merkle=FAIL")
		}
	}
	if rootHashB64, ok := signedRoot["root_hash_b64"].(string); ok && rootHashB64 != "" {
		hints = append(hints, fmt.Sprintf("root=%s…", sanitizeForDisplay(truncateRunes(rootHashB64, 12))))
	}
	suffix := ""
	if len(hints) > 0 {
		suffix = "; " + strings.Join(hints, ", ")
	}
	return fmt.Sprintf("Record %s: %s (%s%s)", sanitizeForDisplay(rec.RecordID), statusLabel(rec.Status), rec.Detail, suffix)
}

// verdictLine renders the single, unambiguous trailing summary line for
// exitCode, mirroring auditverify.Result.ExitCode's documented convention
// (0 = complete and verified, 1 = tampered/failed, 2 = no sealed records to
// verify). Any other value (not currently produced by VerifyBundle) falls
// back to the generic FAILED wording rather than silently omitting a
// verdict.
func verdictLine(exitCode int) string {
	switch exitCode {
	case 0:
		return fmt.Sprintf("RESULT: OK (exit %d)", exitCode)
	case 2:
		return fmt.Sprintf("RESULT: UNVERIFIED (exit %d)", exitCode)
	default:
		return fmt.Sprintf("RESULT: FAILED (exit %d)", exitCode)
	}
}

// printResult prints result to w, mirroring the reference Clojure CLI's
// print-result output format so the two verifiers are interchangeable in
// scripts that parse or diff their output.
func printResult(w io.Writer, result auditverify.Result) {
	for _, rec := range result.Records {
		signedRoot := result.SignedRoot
		if rec.RootID != "" {
			if sr, ok := result.SignedRootsByID[rec.RootID]; ok {
				signedRoot = sr
			}
		}
		mustFprintln(w, formatRecordLine(rec, signedRoot))
	}

	if result.RootSigOK {
		mustFprintln(w, "Root signature: OK")
	} else {
		mustFprintln(w, "Root signature: TAMPERED (signature verification failed)")
	}

	chainLabel := "FAIL"
	switch result.ChainOK {
	case auditverify.ChainOK:
		chainLabel = "OK"
	case auditverify.ChainCaveat:
		chainLabel = "CAVEAT"
	}
	mustFprintf(w, "Chain continuity: %s — %s\n", chainLabel, result.ChainDetail)

	if result.FloorOK != nil && !*result.FloorOK {
		mustFprintln(w, "Retention floor: WARNING — record seq below authorized floor")
	} else if result.FloorOK == nil {
		mustFprintln(w, "Retention floor: ERROR — could not parse retention_policy")
	}

	if result.ImmudbResult != nil {
		switch result.ImmudbResult.Status {
		case auditverify.AnchorVerified:
			mustFprintf(w, "immudb anchor: VERIFIED — %s\n", result.ImmudbResult.Detail)
		case auditverify.AnchorFailed:
			mustFprintf(w, "immudb anchor: FAILED — %s\n", result.ImmudbResult.Detail)
		case auditverify.AnchorSkipped:
			mustFprintf(w, "immudb anchor: SKIPPED — %s\n", result.ImmudbResult.Detail)
		}
	}

	if result.S3Result != nil {
		switch result.S3Result.Status {
		case auditverify.AnchorVerified:
			mustFprintf(w, "s3 anchor: VERIFIED — %s\n", result.S3Result.Detail)
		case auditverify.AnchorFailed:
			mustFprintf(w, "s3 anchor: FAILED — %s\n", result.S3Result.Detail)
		case auditverify.AnchorSkipped:
			mustFprintf(w, "s3 anchor: SKIPPED — %s\n", result.S3Result.Detail)
		}
	}

	mustFprintf(w, "Result set: %s\n", result.SetStatus)

	// A single, unambiguous trailing verdict line driven directly by the
	// exit code (i-40fn): some component lines above -- e.g. "Result set:
	// complete" alongside a retention-parse failure -- are each correct in
	// isolation but can look contradictory next to a non-zero exit code
	// with nothing tying the two together.
	mustFprintln(w, verdictLine(result.ExitCode))

	if len(result.AnchorCmds) > 0 {
		mustFprintln(w)
		mustFprintln(w, "Anchor verification commands:")
		types := make([]string, 0, len(result.AnchorCmds))
		for t := range result.AnchorCmds {
			types = append(types, t)
		}
		sort.Strings(types)
		for _, t := range types {
			mustFprintf(w, "  [%s] %s\n", t, result.AnchorCmds[t])
		}
	}
}
