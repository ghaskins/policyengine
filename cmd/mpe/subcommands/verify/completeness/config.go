//
//  Copyright © Manetu Inc. All rights reserved.
//

package completeness

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/manetu/policyengine/pkg/audit/scan"
	auditverify "github.com/manetu/policyengine/pkg/audit/verify"
	"github.com/urfave/cli/v3"
)

// maxKeyFileBytes bounds how much this CLI will read from any
// operator-supplied key file -- mirrors mpe verify record's maxInputBytes
// defense-in-depth cap against an accidental (or adversarial) oversized
// input exhausting memory.
var maxKeyFileBytes int64 = 256 * 1024 * 1024

func readCappedFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- CLI tool intentionally reads user-provided paths
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only fd; nothing to react to on close failure
	return io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
}

func loadPublicKeyFile(path string) (interface{}, error) {
	data, err := readCappedFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxKeyFileBytes {
		return nil, fmt.Errorf("key file exceeds %d byte limit", maxKeyFileBytes)
	}
	return auditverify.ParsePublicKey(string(data))
}

// parsePartitions parses a comma-separated list of partition indices and/or
// inclusive ranges ("M-N") into a sorted, deduplicated slice, e.g.
// "0,2,4-6" -> [0 2 4 5 6].
func parsePartitions(raw string) ([]int, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("--partitions is required")
	}
	seen := map[int]bool{}
	var out []int
	add := func(n int) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.Index(part, "-"); idx > 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(part[:idx]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(part[idx+1:]))
			if err1 != nil || err2 != nil || hi < lo {
				return nil, fmt.Errorf("invalid --partitions range %q", part)
			}
			for n := lo; n <= hi; n++ {
				add(n)
			}
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid --partitions value %q: %w", part, err)
		}
		add(n)
	}
	sort.Ints(out)
	return out, nil
}

func parseEpochMillisFlag(flagName string, raw string) (int64, error) {
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid --%s value %q: %w", flagName, raw, err)
	}
	return v, nil
}

// builtConfig is buildConfig's output: the fully-resolved scan.Config plus
// the pieces Run needs again after Scan returns (the anchor client, to
// re-enumerate a finding's window when assembling a counter-example bundle;
// the output path to write it to).
type builtConfig struct {
	scanCfg    scan.Config
	anchor     scan.AnchorClient
	outputPath string
}

// buildConfig validates and resolves every flag into buildConfig's fields,
// or returns an error describing exactly which flag is missing/invalid --
// Run maps any such error to exit 3, mirroring mpe verify record's
// config/key-load error convention.
func buildConfig(ctx context.Context, cmd *cli.Command) (*builtConfig, error) {
	partitions, err := parsePartitions(cmd.String("partitions"))
	if err != nil {
		return nil, err
	}

	if !cmd.IsSet("from-ts") {
		return nil, fmt.Errorf("--from-ts is required")
	}
	fromTS, err := parseEpochMillisFlag("from-ts", cmd.String("from-ts"))
	if err != nil {
		return nil, err
	}
	if !cmd.IsSet("to-ts") {
		return nil, fmt.Errorf("--to-ts is required")
	}
	toTS, err := parseEpochMillisFlag("to-ts", cmd.String("to-ts"))
	if err != nil {
		return nil, err
	}
	if toTS <= fromTS {
		return nil, fmt.Errorf("--to-ts (%d) must be greater than --from-ts (%d)", toTS, fromTS)
	}

	notaryKeyPath := cmd.String("notary-public-key")
	if notaryKeyPath == "" {
		return nil, fmt.Errorf("--notary-public-key is required")
	}
	notaryPubKey, err := loadPublicKeyFile(notaryKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load notary public key: %w", err)
	}

	notaryURL := cmd.String("notary-url")
	if notaryURL == "" {
		return nil, fmt.Errorf("--notary-url is required")
	}

	trustedNowMs := time.Now().UnixMilli()
	if cmd.IsSet("trusted-now") {
		trustedNowMs, err = parseEpochMillisFlag("trusted-now", cmd.String("trusted-now"))
		if err != nil {
			return nil, err
		}
	}

	var anchor scan.AnchorClient
	var anchorPubKey interface{}
	switch anchorType := cmd.String("anchor-type"); anchorType {
	case "s3":
		anchor, err = buildS3Client(ctx, cmd)
	case "immudb":
		anchor, anchorPubKey, err = buildImmudbClient(cmd)
	case "":
		return nil, fmt.Errorf("--anchor-type is required (s3 or immudb)")
	default:
		return nil, fmt.Errorf("invalid --anchor-type %q (must be s3 or immudb)", anchorType)
	}
	if err != nil {
		return nil, err
	}

	outputPath := cmd.String("output")
	if outputPath == "" {
		outputPath = "completeness-counterexample.json"
	}

	return &builtConfig{
		scanCfg: scan.Config{
			Partitions:               partitions,
			FromTS:                   fromTS,
			ToTS:                     toTS,
			Anchor:                   anchor,
			Notary:                   &scan.NotaryClient{BaseURL: notaryURL, AuthHeader: cmd.String("notary-auth-header")},
			NotaryPubKey:             notaryPubKey,
			AnchorPubKey:             anchorPubKey,
			TrustedNowMs:             trustedNowMs,
			Concurrency:              cmd.Int("concurrency"),
			RecordExistenceBatchSize: cmd.Int("record-existence-batch-size"),
		},
		anchor:     anchor,
		outputPath: outputPath,
	}, nil
}

func buildS3Client(ctx context.Context, cmd *cli.Command) (scan.AnchorClient, error) {
	bucket := cmd.String("s3-bucket")
	if bucket == "" {
		return nil, fmt.Errorf("--s3-bucket is required when --anchor-type=s3")
	}
	accessKey := cmd.String("s3-access-key-id")
	secretKey := cmd.String("s3-secret-access-key")
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("--s3-access-key-id and --s3-secret-access-key are required when --anchor-type=s3")
	}
	client, err := scan.NewS3Client(ctx, scan.S3Config{
		Bucket:          bucket,
		Region:          cmd.String("s3-region"),
		Endpoint:        cmd.String("s3-endpoint"),
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		PathStyleAccess: cmd.Bool("s3-path-style"),
		CACertPath:      cmd.String("s3-ca-cert"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create s3 anchor client: %w", err)
	}
	return client, nil
}

func buildImmudbClient(cmd *cli.Command) (scan.AnchorClient, interface{}, error) {
	host := cmd.String("immudb-host")
	if host == "" {
		return nil, nil, fmt.Errorf("--immudb-host is required when --anchor-type=immudb")
	}
	port := cmd.Int("immudb-port")
	if port == 0 {
		return nil, nil, fmt.Errorf("--immudb-port is required when --anchor-type=immudb")
	}
	database := cmd.String("immudb-database")
	if database == "" {
		return nil, nil, fmt.Errorf("--immudb-database is required when --anchor-type=immudb")
	}
	username := cmd.String("immudb-username")
	password := cmd.String("immudb-password")
	if username == "" || password == "" {
		return nil, nil, fmt.Errorf("--immudb-username and --immudb-password are required when --anchor-type=immudb")
	}
	keyPath := cmd.String("immudb-public-key")
	if keyPath == "" {
		return nil, nil, fmt.Errorf("--immudb-public-key is required when --anchor-type=immudb")
	}
	pubKey, err := loadPublicKeyFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load immudb public key: %w", err)
	}
	client, err := scan.NewImmudbClient(scan.ImmudbConfig{
		Host:          host,
		Port:          port,
		Database:      database,
		Username:      username,
		Password:      password,
		CACertPath:    cmd.String("immudb-ca-cert"),
		AllowInsecure: cmd.Bool("immudb-allow-insecure"),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create immudb anchor client: %w", err)
	}
	return client, pubKey, nil
}
