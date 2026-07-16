//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package record implements the "mpe verify record" subcommand: a thin CLI
// wrapper around pkg/audit/verify that offline-verifies a Manetu audit
// verification bundle against out-of-band trust roots. Flags and exit codes
// mirror the reference Clojure verify-bundle CLI (service/scripts/verify-bundle
// in mpe-iam-lite) so operators can move between the two without relearning
// options. See docs/docs/reference/cli/verify.md for user-facing
// documentation and docs/docs/reference/verification-bundle-schema.md for
// the bundle format.
package record

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	auditverify "github.com/manetu/policyengine/pkg/audit/verify"
	"github.com/urfave/cli/v3"
)

// Flags registers the mpe verify record subcommand's flags.
var Flags = []cli.Flag{
	&cli.StringFlag{
		Name:    "public-key",
		Aliases: []string{"k"},
		Usage:   "Path to PEM-encoded notary signing public key (required)",
	},
	&cli.StringFlag{
		Name:    "bundle",
		Aliases: []string{"b"},
		Usage:   "Path to bundle JSON; omit or use - for stdin",
	},
	&cli.StringFlag{
		Name:    "immudb-public-key",
		Aliases: []string{"i"},
		Usage:   "Path to PEM-encoded immudb server public key (out-of-band trust root for anchor validation)",
	},
	&cli.StringFlag{
		Name:    "require-anchor",
		Aliases: []string{"a"},
		Usage:   "Comma-separated anchor types (immudb,s3) that must be present and verifiable; a listed anchor entirely absent from the bundle, or (immudb only) present without its corresponding public-key flag, is exit 1",
	},
	&cli.StringFlag{
		Name:    "trusted-now",
		Aliases: []string{"n"},
		Usage:   "Epoch milliseconds for 'now' (default: current time)",
	},
}

// Usage documents the subcommand's exit-code convention, matching the
// reference Clojure verify-bundle CLI exactly.
func Usage() string {
	return strings.Join([]string{
		"Offline-verifies a Manetu audit verification bundle against out-of-band trust roots.",
		"",
		"Usage: mpe verify record --public-key <key.pem> [--immudb-public-key <key.pem>] [--bundle <bundle.json>]",
		"",
		"Exit codes:",
		"  0  all records VERIFIED, set COMPLETE",
		"  1  tampering detected, or immudb/s3 proof invalid (immudb only when",
		"     --immudb-public-key was provided; s3 needs no key), or a",
		"     --require-anchor type is absent from the bundle or (immudb only)",
		"     present without its corresponding public-key flag, or the root",
		"     hash-chain link failed to verify, or the bundle's",
		"     retention_policy.mode could not be parsed",
		"  2  UNVERIFIED-NOT-SEALED (pre-enablement or feature disabled)",
		"  3  bundle parse / key load error",
	}, "\n")
}

// Execute is the mpe verify record subcommand's cli.ActionFunc. Unlike other
// mpe subcommands, record cannot signal its outcome via a returned error: it
// needs exit codes 0-3 (see Usage), and a non-nil error from an urfave/cli
// Action always maps to exit 1 in cmd/mpe/main.go. Execute therefore prints
// directly to stdout/stderr and exits the process itself; Run below holds
// the testable logic.
func Execute(_ context.Context, cmd *cli.Command) error {
	code := Run(cmd, os.Stdout, os.Stderr)
	os.Exit(code)
	return nil // unreachable
}

// Run performs the verification and returns the process exit code. It is
// separated from Execute so tests can exercise it without forking a
// subprocess to observe os.Exit.
func Run(cmd *cli.Command, stdout, stderr io.Writer) int {
	publicKeyPath := cmd.String("public-key")
	if publicKeyPath == "" {
		mustFprintln(stderr, "Error: --public-key is required")
		mustFprintln(stderr, Usage())
		return 3
	}

	pubKey, err := loadPublicKeyFile(publicKeyPath)
	if err != nil {
		mustFprintf(stderr, "Error: failed to load public key: %v\n", err)
		return 3
	}

	immudbPubKey, err := loadOptionalPublicKeyFile(cmd.String("immudb-public-key"))
	if err != nil {
		mustFprintf(stderr, "Error: failed to load immudb public key: %v\n", err)
		return 3
	}

	requireAnchor, err := parseRequireAnchor(cmd.String("require-anchor"))
	if err != nil {
		mustFprintf(stderr, "Error: %v\n", err)
		return 3
	}

	bundleBytes, err := loadBundle(cmd.String("bundle"))
	if err != nil {
		mustFprintf(stderr, "Error: failed to load bundle: %v\n", err)
		return 3
	}
	bundle, err := auditverify.DecodeBundle(bundleBytes)
	if err != nil {
		mustFprintf(stderr, "Error: %v\n", err)
		return 3
	}

	trustedNowMs := time.Now().UnixMilli()
	if cmd.IsSet("trusted-now") {
		raw := cmd.String("trusted-now")
		trustedNowMs, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			mustFprintf(stderr, "Error: invalid --trusted-now value %q: %v\n", raw, err)
			return 3
		}
	}

	result, err := auditverify.VerifyBundle(bundle, pubKey, trustedNowMs, auditverify.Options{
		ImmudbPublicKey: immudbPubKey,
		RequireAnchor:   requireAnchor,
	})
	if err != nil {
		mustFprintf(stderr, "Error: %v\n", err)
		return 3
	}

	printResult(stdout, result)
	return result.ExitCode
}

// maxInputBytes bounds how much this CLI will read from any single
// operator-supplied input (bundle or key file/stdin) -- defense in depth
// against an accidental (or adversarial) multi-gigabyte input exhausting
// memory. Real bundles and PEM keys are, at most, a few MB even for large
// set bundles; this cap is generous relative to that. A var, not a const,
// so tests can shrink it rather than constructing a multi-hundred-MB fixture.
var maxInputBytes int64 = 256 * 1024 * 1024 // 256 MiB

// readCappedFile reads path through a bounded reader so an oversized (or
// unbounded, e.g. a FIFO) file is rejected without first allocating its full
// contents -- os.ReadFile alone would read the whole file into memory
// before any size check could run, defeating maxInputBytes' purpose as a
// memory-exhaustion guard for file inputs the same way it already does for
// stdin (see loadBundle).
func readCappedFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- CLI tool intentionally reads user-provided paths
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only fd; nothing to react to on close failure
	// Read one byte past the cap so an oversized input is detected (rather
	// than silently truncated and handed to the parser as a
	// truncated-but-parseable-looking prefix).
	return io.ReadAll(io.LimitReader(f, maxInputBytes+1))
}

// loadPublicKeyFile reads and parses a PEM public key from path.
func loadPublicKeyFile(path string) (interface{}, error) {
	data, err := readCappedFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxInputBytes {
		return nil, fmt.Errorf("key file exceeds %d byte limit", maxInputBytes)
	}
	return auditverify.ParsePublicKey(string(data))
}

// loadOptionalPublicKeyFile is like loadPublicKeyFile but returns (nil, nil)
// when path is empty.
func loadOptionalPublicKeyFile(path string) (interface{}, error) {
	if path == "" {
		return nil, nil
	}
	return loadPublicKeyFile(path)
}

// loadBundle reads the bundle JSON from path, or from stdin when path is
// empty or "-". Both sources are capped at maxInputBytes.
func loadBundle(path string) ([]byte, error) {
	var data []byte
	var err error
	if path == "" || path == "-" {
		// Read one byte past the cap so an oversized input is detected
		// (rather than silently truncated and handed to the JSON decoder as
		// a truncated-but-parseable-looking prefix).
		data, err = io.ReadAll(io.LimitReader(os.Stdin, maxInputBytes+1))
	} else {
		data, err = readCappedFile(path)
	}
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxInputBytes {
		return nil, fmt.Errorf("bundle exceeds %d byte limit", maxInputBytes)
	}
	return data, nil
}

// parseRequireAnchor parses a comma-separated anchor-type list
// (e.g. "immudb,s3") into an auditverify.RequireAnchor. Requiring both
// types together is rejected outright: a root is anchored to exactly one
// backend (the notary's anchor.backend is a single configured choice, never
// fan-out), so requiring both would demand something no genuine bundle can
// ever satisfy, matching the reference Clojure CLI's behavior.
func parseRequireAnchor(raw string) (auditverify.RequireAnchor, error) {
	var req auditverify.RequireAnchor
	if raw == "" {
		return req, nil
	}
	for _, part := range strings.Split(raw, ",") {
		switch strings.TrimSpace(part) {
		case "":
			continue
		case "immudb":
			req.Immudb = true
		case "s3":
			req.S3 = true
		default:
			return req, fmt.Errorf("invalid --require-anchor type %q (must be immudb or s3)", strings.TrimSpace(part))
		}
	}
	if req.Immudb && req.S3 {
		return req, fmt.Errorf("invalid --require-anchor %q: a root is anchored to exactly one backend; immudb and s3 cannot both be required", raw)
	}
	return req, nil
}
