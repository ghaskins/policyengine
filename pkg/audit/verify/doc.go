//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package verify is a self-contained, offline verifier for Manetu audit
// verification bundles (see docs/docs/reference/verification-bundle-schema.md
// for the schema). It has no dependency on OPA, envoy, or any decision-point
// machinery, and no dependency on the immudb SDK -- anchor proofs are
// hand-verified from stdlib primitives only, the same way the canonical
// Clojure implementation does.
//
// A verification bundle is the complete, self-contained artifact needed to
// independently audit a Manetu access-log record: the raw protobuf record,
// its per-record signature, a Merkle inclusion proof, the signed batch root,
// and references to external anchors (immudb, S3/MinIO). See
// docs/docs/reference/verification-bundle-schema.md for the full schema and
// a step-by-step description of the algorithm this package implements:
//
//  1. Leaf-hash recomputation (SHA-256 over the raw record protobuf bytes).
//  2. Per-record Ed25519 or ECDSA P-256 signature verification.
//  3. RFC 6962 Merkle inclusion proof verification, over the positioned leaf
//     preimage (PositionedLeafHash) that binds a record's tree position to
//     its content hash, not the bare leaf hash.
//  4. Signed-root canonical-JSON verification, using the positive 10-field
//     allowlist (SignableRootFields) rather than stripping signature fields.
//  5. Root-chain continuity (prev_root_hash_b64 linking successive roots).
//  6. Retention-floor evaluation (authorized-absent vs. tamper).
//  7. Optional immudb anchor verification (HTree inclusion proof, signed
//     state verification, ALH binding, and entry-hash binding -- four
//     independent sub-proofs, all of which must pass).
//  8. Optional s3 anchor verification (offline content_sha256 binding; no
//     out-of-band key required).
//
// For a multi-record ("set") bundle, VerifyBundle performs steps 1-8 above
// for every record and root the bundle contains, and rolls the results up
// into a single SetStatus (SetComplete only if every record verified and
// nothing else failed). It does NOT derive a completeness verdict from
// tree_size or leaf-index coverage: a static, offline bundle cannot reliably
// prove a record was deleted, as opposed to modified -- see
// docs/docs/reference/verification-bundle-schema.md's "Set bundles carry no
// completeness claim" section. Detecting a record silently dropped from the
// notary's own store is pkg/audit/scan's job (the online, anchor-authoritative
// completeness scan), not this package's.
//
// Entry point: decode a bundle with [DecodeBundle], parse the notary's
// public key with [ParsePublicKey], and call [VerifyBundle].
package verify
