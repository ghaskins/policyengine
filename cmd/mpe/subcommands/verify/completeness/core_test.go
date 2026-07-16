//
//  Copyright © Manetu Inc. All rights reserved.
//

package completeness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/manetu/policyengine/pkg/audit/scan"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func genKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func pemPublicKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func writeTempFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

// freshFlags returns copies of the package-level Flags so each runCmd call
// parses into its own flag instances -- urfave/cli/v3 flags carry parse
// state (e.g. IsSet) on the shared flag struct itself, so reusing Flags's
// pointers directly across calls would leak "was this flag set" state from
// one test's cmd.Run into the next (mirrors verify/record's identical need).
func freshFlags() []cli.Flag {
	fresh := make([]cli.Flag, len(Flags))
	for i, f := range Flags {
		switch v := f.(type) {
		case *cli.StringFlag:
			cp := *v
			fresh[i] = &cp
		case *cli.IntFlag:
			cp := *v
			fresh[i] = &cp
		case *cli.BoolFlag:
			cp := *v
			fresh[i] = &cp
		default:
			fresh[i] = f
		}
	}
	return fresh
}

func runCmd(t *testing.T, args []string) (exitCode int, stdout, stderr string) {
	t.Helper()
	var captured *cli.Command
	cmd := &cli.Command{
		Name:  "completeness",
		Flags: freshFlags(),
		Action: func(_ context.Context, c *cli.Command) error {
			captured = c
			return nil
		},
	}
	require.NoError(t, cmd.Run(context.Background(), append([]string{"completeness"}, args...)))

	var outBuf, errBuf bytes.Buffer
	code := Run(context.Background(), captured, &outBuf, &errBuf)
	return code, outBuf.String(), errBuf.String()
}

func validNotaryKeyPath(t *testing.T, dir string) string {
	t.Helper()
	pub, _ := genKeyPair(t)
	return writeTempFile(t, dir, "notary-key.pem", []byte(pemPublicKey(t, pub)))
}

// baseArgs returns a minimally-valid arg set (partitions/from-ts/to-ts/
// notary-public-key/notary-url) that later tests extend with one deliberately
// broken or missing flag, isolating exactly one validation failure per test.
func baseArgs(t *testing.T, dir string) []string {
	t.Helper()
	return []string{
		"--partitions", "0",
		"--from-ts", "0",
		"--to-ts", "100",
		"--notary-public-key", validNotaryKeyPath(t, dir),
		"--notary-url", "https://iam-lite.internal",
	}
}

// ---------------------------------------------------------------------------
// parsePartitions
// ---------------------------------------------------------------------------

func TestParsePartitions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw     string
		want    []int
		wantErr bool
	}{
		{raw: "0", want: []int{0}},
		{raw: "0,1,2", want: []int{0, 1, 2}},
		{raw: "0,2,4-6", want: []int{0, 2, 4, 5, 6}},
		{raw: "1,1,2", want: []int{1, 2}}, // dedup
		{raw: "2-0", wantErr: true},       // descending range
		{raw: "abc", wantErr: true},
		{raw: "", wantErr: true},
		{raw: "  ", wantErr: true},
	}
	for _, c := range cases {
		got, err := parsePartitions(c.raw)
		if c.wantErr {
			require.Error(t, err, "input %q", c.raw)
			continue
		}
		require.NoError(t, err, "input %q", c.raw)
		require.Equal(t, c.want, got, "input %q", c.raw)
	}
}

// ---------------------------------------------------------------------------
// Run: flag/config validation (exit 3), no network required -- every path
// below fails before any anchor/notary client is ever constructed.
// ---------------------------------------------------------------------------

func TestRun_MissingPartitionsExitsThree(t *testing.T) {
	t.Parallel()
	code, _, stderr := runCmd(t, []string{"--from-ts", "0", "--to-ts", "100"})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "--partitions is required")
}

func TestRun_MissingFromTsExitsThree(t *testing.T) {
	t.Parallel()
	code, _, stderr := runCmd(t, []string{"--partitions", "0", "--to-ts", "100"})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "--from-ts is required")
}

func TestRun_MissingToTsExitsThree(t *testing.T) {
	t.Parallel()
	code, _, stderr := runCmd(t, []string{"--partitions", "0", "--from-ts", "0"})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "--to-ts is required")
}

func TestRun_ToTsNotGreaterThanFromTsExitsThree(t *testing.T) {
	t.Parallel()
	code, _, stderr := runCmd(t, []string{"--partitions", "0", "--from-ts", "100", "--to-ts", "100"})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "must be greater than")
}

func TestRun_MissingNotaryPublicKeyExitsThree(t *testing.T) {
	t.Parallel()
	code, _, stderr := runCmd(t, []string{"--partitions", "0", "--from-ts", "0", "--to-ts", "100"})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "--notary-public-key is required")
}

func TestRun_BadNotaryPublicKeyPathExitsThree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	code, _, stderr := runCmd(t, []string{
		"--partitions", "0", "--from-ts", "0", "--to-ts", "100",
		"--notary-public-key", filepath.Join(dir, "nonexistent.pem"),
	})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "failed to load notary public key")
}

func TestRun_MissingNotaryURLExitsThree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	code, _, stderr := runCmd(t, []string{
		"--partitions", "0", "--from-ts", "0", "--to-ts", "100",
		"--notary-public-key", validNotaryKeyPath(t, dir),
	})
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "--notary-url is required")
}

func TestRun_MissingAnchorTypeExitsThree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	code, _, stderr := runCmd(t, baseArgs(t, dir))
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "--anchor-type is required")
}

func TestRun_InvalidAnchorTypeExitsThree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	args := append(baseArgs(t, dir), "--anchor-type", "bogus")
	code, _, stderr := runCmd(t, args)
	require.Equal(t, 3, code)
	require.Contains(t, stderr, `invalid --anchor-type "bogus"`)
}

func TestRun_S3AnchorMissingBucketExitsThree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	args := append(baseArgs(t, dir), "--anchor-type", "s3")
	code, _, stderr := runCmd(t, args)
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "--s3-bucket is required")
}

func TestRun_S3AnchorMissingCredentialsExitsThree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	args := append(baseArgs(t, dir), "--anchor-type", "s3", "--s3-bucket", "b", "--s3-region", "us-east-1")
	code, _, stderr := runCmd(t, args)
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "--s3-access-key-id and --s3-secret-access-key are required")
}

func TestRun_ImmudbAnchorMissingHostExitsThree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	args := append(baseArgs(t, dir), "--anchor-type", "immudb")
	code, _, stderr := runCmd(t, args)
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "--immudb-host is required")
}

func TestRun_ImmudbAnchorMissingPublicKeyExitsThree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	args := append(baseArgs(t, dir),
		"--anchor-type", "immudb",
		"--immudb-host", "immudb.internal", "--immudb-port", "8080",
		"--immudb-database", "defaultdb", "--immudb-username", "u", "--immudb-password", "p",
	)
	code, _, stderr := runCmd(t, args)
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "--immudb-public-key is required")
}

func TestRun_InvalidTrustedNowExitsThree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	args := append(baseArgs(t, dir),
		"--anchor-type", "s3", "--s3-bucket", "b", "--s3-region", "us-east-1",
		"--s3-access-key-id", "ak", "--s3-secret-access-key", "sk",
		"--trusted-now", "notanumber",
	)
	code, _, stderr := runCmd(t, args)
	require.Equal(t, 3, code)
	require.Contains(t, stderr, "invalid --trusted-now value")
}

// ---------------------------------------------------------------------------
// printResult / firstPinpointedFinding
// ---------------------------------------------------------------------------

func TestPrintResult_CleanScan(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printResult(&buf, scan.Result{
		VerdictTier:      "s3:provider-trusted-worm",
		PartitionsWalked: 2,
		RootsWalked:      5,
		LeavesCensused:   42,
		Partitions: []scan.PartitionSummary{
			{Partition: 0, RootsWalked: 5, LeavesCensused: 42},
			{Partition: 1, Idle: true},
		},
	})
	out := buf.String()
	require.Contains(t, out, "RESULT: OK (exit 0)")
	require.Contains(t, out, "partition 1: 0 roots, 0 leaves (idle)")
	require.NotContains(t, out, "Findings")
}

func TestPrintResult_DiscrepancySurfacesFindingsAndExitCode(t *testing.T) {
	t.Parallel()
	offset := int64(7)
	leafIndex := int64(3)
	var buf bytes.Buffer
	printResult(&buf, scan.Result{
		ExitCode: 2,
		Findings: []scan.Finding{
			{
				Kind: "record-existence", Partition: 0, RootID: "root-0",
				Offset: &offset, LeafIndex: &leafIndex, RecordID: "rec-a",
				Detail: "record is absent from accesslog but still inside the retention window",
			},
		},
	})
	out := buf.String()
	require.Contains(t, out, "[record-existence] partition=0, root_id=root-0, offset=7, leaf_index=3, record_id=rec-a")
	require.Contains(t, out, "RESULT: FAILED (exit 2)")
}

// TestPrintResult_MaliciousFindingFieldsCannotSpoofTerminal mirrors verify
// record's i-33dl regression: every field this CLI renders from a live,
// potentially-compromised source (finding.RecordID/Detail/RootID) must be
// sanitized before reaching the terminal, exactly like a bundle field is.
func TestPrintResult_MaliciousFindingFieldsCannotSpoofTerminal(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printResult(&buf, scan.Result{
		ExitCode: 2,
		Findings: []scan.Finding{
			{
				Kind: "record-existence", Partition: 0, RootID: "root-0",
				RecordID: "rec-a\x1b[2K\x1b[1A\rRESULT: OK (exit 0)",
				Detail:   "d",
			},
		},
	})
	out := buf.String()
	require.NotContains(t, out, "\x1b")
	require.NotContains(t, out, "\r")
}

func TestFirstPinpointedFinding(t *testing.T) {
	t.Parallel()

	findings := []scan.Finding{
		{Kind: "chain"},
		{Kind: "batch-density", RootID: "root-1"},
		{Kind: "record-existence", RootID: "root-2"},
	}
	f, ok := firstPinpointedFinding(findings)
	require.True(t, ok)
	require.Equal(t, "root-1", f.RootID)

	_, ok = firstPinpointedFinding([]scan.Finding{{Kind: "chain"}, {Kind: "tail-truncation"}})
	require.False(t, ok)
}

// ---------------------------------------------------------------------------
// buildCounterExample, against a fake scan.AnchorClient -- exercises this
// CLI's own re-enumeration/assembly glue without needing a live anchor
// backend (pkg/audit/scan's own test suite already covers BuildCounterExample
// Bundle's content rules; this only covers how this package drives it).
// ---------------------------------------------------------------------------

type fakeAnchorClient struct {
	roots   map[int][]scan.EnumeratedRoot
	refs    map[string]map[string]interface{}
	refErr  error
	enumErr error
}

func (f *fakeAnchorClient) Tier() string { return "fake" }

func (f *fakeAnchorClient) AnchorHead(context.Context, int) (*scan.AnchorPointer, error) {
	return nil, nil
}

func (f *fakeAnchorClient) EnumerateRootsInWindow(_ context.Context, partition int, _, _ int64) ([]scan.EnumeratedRoot, error) {
	if f.enumErr != nil {
		return nil, f.enumErr
	}
	return f.roots[partition], nil
}

func (f *fakeAnchorClient) VerifyAnchorProof(context.Context, scan.EnumeratedRoot, interface{}) (scan.AnchorProofResult, error) {
	return scan.AnchorProofResult{OK: true}, nil
}

func (f *fakeAnchorClient) AnchorRef(_ context.Context, root scan.EnumeratedRoot) (map[string]interface{}, error) {
	if f.refErr != nil {
		return nil, f.refErr
	}
	return f.refs[root.RootID], nil
}

func TestBuildCounterExample_EmbedsPrevRootAndAnchorRefs(t *testing.T) {
	t.Parallel()

	root0 := scan.EnumeratedRoot{RootID: "root-0", Payload: map[string]interface{}{"root_hash_b64": "aaaa"}}
	root1 := scan.EnumeratedRoot{RootID: "root-1", Payload: map[string]interface{}{"prev_root_id": "root-0"}}
	anchor := &fakeAnchorClient{
		roots: map[int][]scan.EnumeratedRoot{0: {root0, root1}},
		refs:  map[string]map[string]interface{}{"root-1": {"s3": map[string]interface{}{"key": "x"}}},
	}
	finding := scan.Finding{Kind: "record-existence", Partition: 0, RootID: "root-1"}

	bundle, err := buildCounterExample(context.Background(), anchor, 0, 1000, finding)
	require.NoError(t, err)
	require.Equal(t, root1.Payload, bundle["signed_root"])
	require.Equal(t, root0.Payload, bundle["prev_signed_root"])
	require.NotNil(t, bundle["anchor_refs"])
}

func TestBuildCounterExample_RootNoLongerPresentErrors(t *testing.T) {
	t.Parallel()

	anchor := &fakeAnchorClient{roots: map[int][]scan.EnumeratedRoot{0: {}}}
	finding := scan.Finding{Kind: "record-existence", Partition: 0, RootID: "root-missing"}

	_, err := buildCounterExample(context.Background(), anchor, 0, 1000, finding)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no longer present")
}

func TestBuildCounterExample_EnumerateErrorPropagates(t *testing.T) {
	t.Parallel()

	anchor := &fakeAnchorClient{enumErr: context.DeadlineExceeded}
	finding := scan.Finding{Kind: "record-existence", Partition: 0, RootID: "root-1"}

	_, err := buildCounterExample(context.Background(), anchor, 0, 1000, finding)
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
