//
//  Copyright © Manetu Inc. All rights reserved.
//

package record

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCrossImplementationParity is the guard for i-3fho: it asserts that
// mpe verify record (this package) reaches the same verdict -- exit code and
// human-readable status -- as the reference Clojure verify-bundle CLI
// (service/scripts/verify-bundle, backed by
// manetu.iamlite-service.notary.verify-cli in mpe-iam-lite) on identical
// bundle fixtures.
//
// The fixtures under testdata/parity/ are golden: generated once (see the
// package doc comment on the now-deleted fixture generator's history) and
// pinned here, all at bundle-schema-v1.0. Each case's original
// expectedStatus/expectedExitCode (see the per-case comments below, kept as
// historical record) was captured by running the *actual* Clojure
// verify-bundle CLI against the exact same bundle.json/key files at a time
// when both implementations' schema-major was 1.
//
// SCHEMA-2 MIGRATION (s-3vlq/i-4a1z, 2026-08-13): both this Go verifier and
// the reference Clojure verifier have since bumped supportedSchemaMajor
// 1 -> 2 (schema major 2 dropped the set-bundle completeness/
// root_chain_context fields and replaced the retired timestamp_ms
// signable-root field with notary_ts_from/notary_ts_to/partition_count --
// see verify.go's supportedSchemaMajor doc comment). Per this project's "no
// back-compat shims" convention, a pre-2.0 bundle is now correctly refused
// outright at the meta-envelope gate, before any record/root/anchor
// cryptography ever runs -- so these three schema-1.0 golden fixtures (whose
// signatures were computed over the retired 8-field allowlist and cannot be
// re-signed here: only the *public* notary key is checked in under
// testdata/parity/, never the private key that produced these fixtures) now
// all uniformly fail at that gate with exit 3, regardless of which
// content-specific behavior (tampered/unsealed/etc.) each was originally
// built to exercise. This is the expected, correct outcome given both
// implementations now agree schema-major must be 2 -- so the parity property
// this test guards (identical verdict across implementations) still holds,
// just trivially (both refuse identically) -- but it means this suite has
// temporarily lost its ability to cross-check the content-specific verify
// logic. Regenerating genuine schema-2.0 golden fixtures requires running
// the real Clojure verify-bundle CLI (with a real notary signing key)
// against freshly-produced v2.0 bundles; that is tracked separately and is
// NOT done here (no private signing key is available in this sandbox to
// produce a legitimately cross-implementation fixture).
//
// The two Rekor-anchor fixtures this suite originally also carried
// (rekor-failed, rekor-stale-unbound) were removed when Rekor support was
// retired from this verifier (mpe-iam-lite deleted the Rekor witness backend
// outright under spec s-9xga; see pkg/audit/verify's package doc). Both
// exercised only the same schema-1.0 meta-gate refusal the three remaining
// fixtures already cover, so no live behavioral coverage was lost.
func TestCrossImplementationParity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
	}{
		// Verified against the real Clojure verify-bundle CLI (schema-major 1):
		//   Record <bundle-record>: VERIFIED (leaf hash and signature verified; merkle=OK, root=TGCVSOiQW5rj…)
		//   Result set: complete
		//   exit=0
		// Now: exit=3 (schema-1.0 bundle refused at the meta gate; see the
		// SCHEMA-2 MIGRATION note above).
		{name: "verified"},

		// Clojure CLI (schema-major 1):
		//   Record <bundle-record>: TAMPERED (leaf hash mismatch: record_pb has been modified; root=TGCVSOiQW5rj…)
		//   Result set: incomplete
		//   exit=1
		// Now: exit=3 (schema-1.0 bundle refused at the meta gate).
		{name: "tampered"},

		// Clojure CLI (schema-major 1):
		//   Record <bundle-record>: UNVERIFIED-NOT-SEALED (no integrity field (pre-enablement record); root=0yPEBpOWL2M6…)
		//   Result set: incomplete
		//   exit=2
		// Now: exit=3 (schema-1.0 bundle refused at the meta gate).
		{name: "unsealed"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			dir := filepath.Join("testdata", "parity", c.name)
			args := []string{
				"--bundle", filepath.Join(dir, "bundle.json"),
				"--public-key", filepath.Join(dir, "notary-public-key.pem"),
			}

			// All three fixtures are pinned at schema_version 1.0 (see the
			// SCHEMA-2 MIGRATION doc comment above): VerifyBundle now
			// refuses them outright at the meta-envelope gate, before
			// printResult ever runs -- so the verdict lands on stderr as a
			// plain load error (exit 3), not stdout's normal report.
			code, stdout, stderr := runCmd(t, args)
			require.Equal(t, 3, code, "exit code mismatch for fixture %s; stdout:\n%s\nstderr:\n%s", c.name, stdout, stderr)
			require.Contains(t, stderr, "unsupported schema_version", "fixture %s should be refused for its schema-1.0 meta.schema_version", c.name)
		})
	}
}

// TestParityFixturesExist guards against the testdata directory silently
// losing files (e.g. a bad .gitignore rule) -- a passing parity suite with
// zero subtests would otherwise look identical to a real pass.
func TestParityFixturesExist(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(filepath.Join("testdata", "parity"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(entries), 3, "expected at least 3 golden parity fixtures")
}
