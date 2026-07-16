//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package completeness implements the "mpe verify completeness" subcommand:
// a thin CLI wrapper around pkg/audit/scan that runs the online,
// anchor-authoritative completeness scan (mpe-iam-lite spec s-3vlq) directly
// against a live anchor backend (S3 or immudb) and a running iam-lite
// deployment's read-only NDJSON notary proxy. Unlike "mpe verify record" --
// a deliberately offline, self-contained bundle check -- this subcommand
// dials out: it needs real anchor credentials and a reachable iam-lite
// instance. See docs/docs/reference/cli/verify.md for user-facing
// documentation and pkg/audit/scan's package doc comment for the 8-step
// algorithm this command drives.
package completeness

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/manetu/policyengine/pkg/audit/scan"
	"github.com/urfave/cli/v3"
)

// Flags registers the mpe verify completeness subcommand's flags.
var Flags = []cli.Flag{
	&cli.StringFlag{
		Name:    "partitions",
		Aliases: []string{"p"},
		Usage:   "Comma-separated partition indices and/or inclusive ranges to scan, e.g. \"0,2,4-6\" (required)",
	},
	&cli.StringFlag{
		Name:  "from-ts",
		Usage: "Inclusive lower bound of the notary_ts scan window, epoch milliseconds (required)",
	},
	&cli.StringFlag{
		Name:  "to-ts",
		Usage: "Exclusive upper bound of the notary_ts scan window, epoch milliseconds (required)",
	},
	&cli.StringFlag{
		Name:    "notary-public-key",
		Aliases: []string{"k"},
		Usage:   "Path to PEM-encoded notary signing public key (required)",
	},
	&cli.StringFlag{
		Name:  "anchor-type",
		Usage: "Anchor backend to scan directly: s3 or immudb (required)",
	},
	&cli.StringFlag{
		Name:    "immudb-public-key",
		Aliases: []string{"i"},
		Usage:   "Path to PEM-encoded immudb server public key, the anchor's own out-of-band trust root (required when --anchor-type=immudb)",
	},
	&cli.StringFlag{
		Name:  "s3-bucket",
		Usage: "S3 bucket the anchor store writes to (required when --anchor-type=s3)",
	},
	&cli.StringFlag{
		Name:  "s3-region",
		Usage: "S3 region (required when --s3-endpoint is not set)",
	},
	&cli.StringFlag{
		Name:  "s3-endpoint",
		Usage: "S3-compatible endpoint override (e.g. MinIO); empty selects the standard AWS endpoint",
	},
	&cli.StringFlag{
		Name:  "s3-access-key-id",
		Usage: "S3 access key ID (required when --anchor-type=s3)",
	},
	&cli.StringFlag{
		Name:  "s3-secret-access-key",
		Usage: "S3 secret access key (required when --anchor-type=s3)",
	},
	&cli.BoolFlag{
		Name:  "s3-path-style",
		Usage: "Use path-style S3 addressing (required by most S3-compatible endpoints, e.g. MinIO)",
	},
	&cli.StringFlag{
		Name:  "s3-ca-cert",
		Usage: "PEM CA bundle to pin TLS trust for the S3 endpoint; empty uses the system trust store",
	},
	&cli.StringFlag{
		Name:  "immudb-host",
		Usage: "immudb REST gateway host (required when --anchor-type=immudb)",
	},
	&cli.IntFlag{
		Name:  "immudb-port",
		Usage: "immudb REST gateway port (required when --anchor-type=immudb)",
	},
	&cli.StringFlag{
		Name:  "immudb-database",
		Usage: "immudb database name (required when --anchor-type=immudb)",
	},
	&cli.StringFlag{
		Name:  "immudb-username",
		Usage: "immudb username (required when --anchor-type=immudb)",
	},
	&cli.StringFlag{
		Name:  "immudb-password",
		Usage: "immudb password (required when --anchor-type=immudb)",
	},
	&cli.StringFlag{
		Name:  "immudb-ca-cert",
		Usage: "PEM CA bundle to pin TLS trust for immudb; empty + --immudb-allow-insecure selects plain HTTP",
	},
	&cli.BoolFlag{
		Name:  "immudb-allow-insecure",
		Usage: "Allow a plaintext HTTP connection to immudb (development only)",
	},
	&cli.StringFlag{
		Name:  "notary-url",
		Usage: "Base URL of the iam-lite deployment's notary proxy endpoints, e.g. https://iam-lite.internal (required)",
	},
	&cli.StringFlag{
		Name:  "notary-auth-header",
		Usage: "Authorization header value sent on every notary-proxy request, e.g. 'Bearer <token>'",
	},
	&cli.StringFlag{
		Name:    "trusted-now",
		Aliases: []string{"n"},
		Usage:   "Epoch milliseconds for 'now' used to evaluate the retention floor (default: current time)",
	},
	&cli.IntFlag{
		Name:  "concurrency",
		Usage: "How many partitions to scan concurrently (default: number of partitions requested)",
	},
	&cli.IntFlag{
		Name:  "record-existence-batch-size",
		Usage: "How many record ids to send per record-existence request (default: 500)",
	},
	&cli.StringFlag{
		Name:    "output",
		Aliases: []string{"o"},
		Usage:   "Path to write a counter-example bundle if a discrepancy is found (default: completeness-counterexample.json)",
	},
}

// Usage documents the subcommand's exit-code convention.
func Usage() string {
	return strings.Join([]string{
		"Runs the online, anchor-authoritative completeness scan across a notary_ts window.",
		"",
		"Usage: mpe verify completeness --partitions <spec> --from-ts <ms> --to-ts <ms> \\",
		"         --notary-public-key <key.pem> --anchor-type <s3|immudb> [anchor flags] \\",
		"         --notary-url <url> [options]",
		"",
		"Exit codes:",
		"  0  clean scan: every enumerated root, batch, and record checked out",
		"  2  one or more discrepancies found; see the pinpointed finding(s) and,",
		"     when pinpointable, the written counter-example bundle",
		"  3  configuration error, key load error, or a scan infrastructure",
		"     failure (never produced for a genuine tamper finding -- those are",
		"     always exit 2)",
	}, "\n")
}

// Execute is the mpe verify completeness subcommand's cli.ActionFunc. Like
// mpe verify record, completeness signals its outcome via a process exit
// code rather than a returned error (a non-nil error from an urfave/cli
// Action always maps to exit 1 in cmd/mpe/main.go, which would collapse
// exit 2 and exit 3 into the same code); Run below holds the testable logic.
func Execute(ctx context.Context, cmd *cli.Command) error {
	code := Run(ctx, cmd, os.Stdout, os.Stderr)
	os.Exit(code)
	return nil // unreachable
}

// Run performs the completeness scan and returns the process exit code. It
// is separated from Execute so tests can exercise it without forking a
// subprocess to observe os.Exit.
func Run(ctx context.Context, cmd *cli.Command, stdout, stderr io.Writer) int {
	built, err := buildConfig(ctx, cmd)
	if err != nil {
		mustFprintf(stderr, "Error: %v\n", err)
		mustFprintln(stderr, Usage())
		return 3
	}

	result, err := scan.Scan(ctx, built.scanCfg)
	if err != nil {
		mustFprintf(stderr, "Error: %v\n", err)
		return 3
	}

	printResult(stdout, result)

	if finding, ok := firstPinpointedFinding(result.Findings); ok {
		if err := writeCounterExample(ctx, built, finding); err != nil {
			mustFprintf(stderr, "Warning: %v\n", err)
		} else {
			mustFprintf(stdout, "Counter-example bundle written to %s (re-verify with: mpe verify record --public-key <notary-public-key.pem> --bundle %s)\n", built.outputPath, built.outputPath)
		}
	}

	return result.ExitCode
}
