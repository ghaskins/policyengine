//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package scan implements the online, anchor-authoritative completeness scan
// (mpe-iam-lite spec s-3vlq). Unlike pkg/audit/verify -- a deliberately
// stdlib-only, offline, air-gapped bundle verifier -- this package is a live
// scanner: it dials the configured anchor backend (S3 or immudb) directly and
// calls a running iam-lite deployment's read-only NDJSON proxy endpoints
// (/api/v1/notary/leaves, /api/v1/notary/record-existence) for the
// ES-backed steps. Every field the scan reads is self-authenticating (hash-
// or signature-checked downstream), so a compromised iam-lite service can
// only omit evidence, never forge it -- omission is exactly what the scan is
// built to catch.
//
// Per partition, for a requested notary_ts window [from_ts, to_ts), Scan
// performs 8 steps:
//
//  1. Enumerate roots via the anchor's EnumerateRootsInWindow (direct
//     S3/immudb client).
//  2. Verify each root's signature and its prev_root_id/root_hash_b64 chain
//     link to its predecessor.
//  3. Verify each root's own anchor-inclusion proof (immudb's 4-part
//     ALH-binding/entry_hash/state-signature check, or S3's WORM/checksum
//     binding) -- the same depth pkg/audit/verify applies offline.
//  4. Verify offset contiguity across the enumerated roots, with a
//     degenerate-range exception for heartbeat roots (tree_size == 0).
//  5. Verify the tail: the last enumerated root's covered_range.to_seq must
//     equal the anchor's own head pointer -- an anchor ahead of the last
//     enumerated root means roots were withheld.
//  6. Verify partition_count coverage across 0..N-1 (idle vs.
//     whole-partition-drop).
//  7. Verify batch density: fetch each non-heartbeat root's leaf list via the
//     iam-lite leaves endpoint, recompute the position-bound Merkle root
//     (Design D1: notary/hash.clj's positioned-leaf-hash, NOT the raw
//     per-record content hash), and require equality with the
//     anchor-fetched root_hash_b64.
//  8. Verify record existence via the iam-lite record-existence endpoint,
//     retention-floor-aware (a record legitimately retired by ILM must not
//     read as tamper evidence).
//
// A step 7/8 failure pinpoints the exact (partition, offset, leaf_index,
// root_id) and can be rendered into a portable counter-example bundle (see
// BuildCounterExampleBundle) -- a record-kind offline bundle, independently
// re-verifiable via `mpe verify record`.
package scan
