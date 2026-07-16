//go:build integration

//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan_test

// This file is intentionally build-tag gated (`integration`) and NOT run by
// `go test ./...` or by this package's own unit suite -- it requires a live
// mpe-iam-lite deployment backed by real docker dependencies
// (`make sociable-test` in the mpe-iam-lite repo: real ES, immudb, and
// MinIO/S3), plus the notary write pipeline actually producing signed
// batches, which this Go-only sandbox does not stand up. Wiring and running
// it live against `make sociable-test`'s docker deps -- including driving
// both new tamper-evidence attacks (deleting a leaf from manetu-notary-leaf
// only, and deleting a record from manetu-accesslog only, and confirming
// scan steps 7/8 respectively catch each) -- is tracked as follow-up work,
// not completed in this session. See the C7 issue's sudocode feedback for
// the honest status of this acceptance-criteria item.
//
// Intended shape once wired (do not treat the below as verified -- it is a
// documented starting point, not a working test):
//
//   func TestScanEndToEndAgainstSociableDeps(t *testing.T) {
//       // 1. Point an S3Client at the sociable-test MinIO endpoint/bucket
//       //    and credentials (docker-compose.sociable.yaml exposes these).
//       // 2. Point an ImmudbClient at the sociable-test immudb REST gateway.
//       // 3. Point a NotaryClient at a running iam-lite service instance
//       //    with audit_integrity enabled, proxying to the same ES.
//       // 4. Drive real AccessRecord writes through the signer/batcher so at
//       //    least one real signed batch root exists in both anchors.
//       // 5. Run scan.Scan with real trust roots (the deployment's notary
//       //    and immudb public keys) and assert ExitCode == 0, Findings
//       //    empty.
//       // 6. Attack 1: delete one leaf-index document from
//       //    manetu-notary-leaf directly (not accesslog) for a sealed batch;
//       //    re-run Scan; assert a "batch-density" Finding pinpoints that
//       //    root, and BuildCounterExampleBundle + WriteCounterExampleBundle
//       //    + pkg/audit/verify.VerifyBundle round-trips it.
//       // 7. Attack 2: delete one record from manetu-accesslog directly
//       //    (leaving its leaf-index entry and anchor untouched); re-run
//       //    Scan; assert a "record-existence" Finding pinpoints the exact
//       //    (partition, offset, leaf_index, root_id) and round-trips.
//   }
