//
//  Copyright © Manetu Inc. All rights reserved.
//

package completeness

import (
	"context"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/manetu/policyengine/pkg/audit/scan"
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

// sanitizeForDisplay strips control and non-printable runes from a field
// this CLI read from a live, potentially-compromised source (the notary
// proxy or the anchor backend) before it reaches the terminal -- mirrors
// mpe verify record's i-33dl defense: per this tool's own threat model,
// nothing fetched live is more trustworthy than a bundle field, and both
// get the same terminal-injection guard.
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

// printResult renders result's summary, per-partition tally, and (on a
// discrepancy) every finding, ending in the same single, unambiguous
// trailing RESULT: line convention mpe verify record uses so both
// subcommands stay script-parseable the same way.
func printResult(w io.Writer, result scan.Result) {
	mustFprintf(w, "Anchor tier: %s\n", sanitizeForDisplay(result.VerdictTier))
	mustFprintf(w, "Partitions walked: %d, roots walked: %d, leaves censused: %d\n",
		result.PartitionsWalked, result.RootsWalked, result.LeavesCensused)
	for _, p := range result.Partitions {
		state := ""
		if p.Idle {
			state = " (idle)"
		}
		mustFprintf(w, "  partition %d: %d roots, %d leaves%s\n", p.Partition, p.RootsWalked, p.LeavesCensused, state)
	}

	if len(result.Findings) == 0 {
		mustFprintln(w, "RESULT: OK (exit 0)")
		return
	}

	mustFprintln(w, "Findings:")
	for _, f := range result.Findings {
		pinpoint := ""
		if f.Offset != nil && f.LeafIndex != nil {
			pinpoint = fmt.Sprintf(", offset=%d, leaf_index=%d", *f.Offset, *f.LeafIndex)
		}
		recordID := ""
		if f.RecordID != "" {
			recordID = fmt.Sprintf(", record_id=%s", sanitizeForDisplay(f.RecordID))
		}
		mustFprintf(w, "  [%s] partition=%d, root_id=%s%s%s: %s\n",
			f.Kind, f.Partition, sanitizeForDisplay(f.RootID), pinpoint, recordID, sanitizeForDisplay(f.Detail))
	}
	mustFprintf(w, "RESULT: FAILED (exit %d)\n", result.ExitCode)
}

// firstPinpointedFinding returns the first finding in findings whose Kind
// carries a (partition, root_id) BuildCounterExampleBundle can turn into a
// portable, independently re-verifiable artifact (s-3vlq decision 7) --
// "batch-density" or "record-existence". The earlier structural findings
// (root-signature, chain, anchor-proof, contiguity, tail-truncation,
// partition-coverage) have no single root or record to build a bundle
// around, so they are reported (see printResult) but never bundled.
func firstPinpointedFinding(findings []scan.Finding) (scan.Finding, bool) {
	for _, f := range findings {
		if f.Kind == "batch-density" || f.Kind == "record-existence" {
			return f, true
		}
	}
	return scan.Finding{}, false
}

// buildCounterExample re-enumerates finding.Partition's window to recover
// the signed root -- and, when available, its predecessor, so
// BuildCounterExampleBundle can embed it for a recursive chain re-check --
// that scan.Result no longer carries once reduced from a live scan to a
// summary. record is always nil: the notary proxy's record-existence
// response never discloses a record's raw bytes (s-3vlq decision 5 lists
// exactly {id, found, leaf_hash_b64, signature_b64}), so a "batch-density"
// finding's bundle proves the batch's inclusion is untrustworthy without
// asserting which specific record was at fault, and a "record-existence"
// finding's bundle is a proof of absence by construction -- both are honest,
// re-verifiable outcomes per BuildCounterExampleBundle's own doc comment.
func buildCounterExample(ctx context.Context, anchor scan.AnchorClient, fromTS, toTS int64, finding scan.Finding) (map[string]interface{}, error) {
	roots, err := anchor.EnumerateRootsInWindow(ctx, finding.Partition, fromTS, toTS)
	if err != nil {
		return nil, fmt.Errorf("re-fetching partition %d's roots: %w", finding.Partition, err)
	}
	var root scan.EnumeratedRoot
	var prevRoot *scan.EnumeratedRoot
	found := false
	for i, r := range roots {
		if r.RootID == finding.RootID {
			root = r
			found = true
			if i > 0 {
				pr := roots[i-1]
				prevRoot = &pr
			}
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("root %q is no longer present in partition %d's window (anchor state changed since the scan ran)", finding.RootID, finding.Partition)
	}
	anchorRefs, err := anchor.AnchorRef(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("fetching anchor_refs for root %q: %w", finding.RootID, err)
	}
	return scan.BuildCounterExampleBundle(finding, root, prevRoot, anchorRefs, nil)
}

// writeCounterExample builds and writes finding's counter-example bundle to
// built.outputPath. A failure here (e.g. the anchor's state moved on since
// the scan ran, or the output path is unwritable) is reported as a warning,
// not an exit-3 error: the scan itself already completed and its exit code
// (2) must still reflect the genuine discrepancy it found, with or without
// a portable artifact to go with it.
func writeCounterExample(ctx context.Context, built *builtConfig, finding scan.Finding) error {
	bundle, err := buildCounterExample(ctx, built.anchor, built.scanCfg.FromTS, built.scanCfg.ToTS, finding)
	if err != nil {
		return fmt.Errorf("failed to build counter-example bundle: %w", err)
	}
	if err := scan.WriteCounterExampleBundle(built.outputPath, bundle); err != nil {
		return fmt.Errorf("failed to write counter-example bundle to %s: %w", built.outputPath, err)
	}
	return nil
}
