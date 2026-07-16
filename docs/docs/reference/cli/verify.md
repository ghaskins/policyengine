---
sidebar_position: 6
---

# mpe verify

Verify Manetu audit tamper-evidence: per-record, offline (`record`), or completeness, online and
anchor-authoritative (`completeness`).

`mpe verify` itself ships in the Community CLI at no cost — it is a pure verifier with no
dependency on a live PolicyEngine deployment. The **artifacts** it verifies (verification bundles,
notarized batch roots, external anchors) are produced by the <FeatureChip variant="premium" />
audit-integrity (tamper-evident notary) feature described in [Audit & Access
Records](/concepts/audit). Without that feature enabled on the deployment that wrote a record,
there is nothing for `mpe verify` to check.

## Synopsis

```bash
mpe verify record --public-key <key.pem> [--bundle <bundle.json>] [options]
mpe verify completeness --partitions <spec> --from-ts <ms> --to-ts <ms> \
  --notary-public-key <key.pem> --anchor-type <s3|immudb> [anchor options] \
  --notary-url <url> [options]
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `record` | Offline-verify a single-record or set bundle against out-of-band trust roots |
| `completeness` | Run the online, anchor-authoritative completeness scan across a notary_ts window |

Both subcommands check different halves of the same tamper-evidence story. `record` proves that a
given record, once you already have it, has not been modified. `completeness` proves that nothing
was silently deleted — a static, offline artifact cannot prove that negative, so completeness is
necessarily an online check against a live deployment's anchor and notary state. See the
[Verification Bundle Schema](/reference/verification-bundle-schema) reference for the algorithm
`record` implements.

## verify record

Offline-verify a Manetu audit verification bundle against out-of-band trust roots.

### Description

`verify record` is a standalone, offline verifier for **audit verification bundles** produced by a
Manetu PolicyEngine deployment with the audit-integrity (tamper-evident notary) feature enabled. It
independently re-derives and checks a bundle's cryptographic evidence — per-record signature,
Merkle inclusion proof, signed batch root, and the external anchor (immudb or S3/MinIO — a
deployment configures exactly one) — without contacting a live service.

`verify record` trusts **only** the out-of-band public key(s) supplied on the command line. It
never reads a trust root from the bundle itself or from a live endpoint — a bundle or a live
service is exactly what an adversary controls under the notary's threat model, so trusting a key
from either would let an adversary supply their own key alongside a forged proof.

### Options

| Option | Alias | Description | Required |
|--------|-------|-------------|----------|
| `--public-key` | `-k` | Path to PEM-encoded notary signing public key | Yes |
| `--bundle` | `-b` | Path to bundle JSON; omit or use `-` for stdin | No |
| `--immudb-public-key` | `-i` | Path to PEM-encoded immudb server public key (out-of-band trust root for immudb anchor validation) | No |
| `--require-anchor` | `-a` | Comma-separated anchor types (`immudb`, `s3`) that must be present and verifiable; a listed anchor entirely absent from the bundle, or (immudb only) present without its corresponding public-key flag, fails closed. A root is anchored to exactly one backend, so requiring both types together is rejected outright (exit 3). | No |
| `--trusted-now` | `-n` | Epoch milliseconds for "now" used to evaluate the retention floor (default: current time) | No |

The bundle (file or stdin) and every PEM key file are each capped at 256 MiB; an oversized input is
rejected rather than silently truncated.

### Examples

#### Verify a Bundle File

```bash
mpe verify record --public-key notary-public-key.pem --bundle bundle.json
```

#### Verify From Stdin

```bash
cat bundle.json | mpe verify record --public-key notary-public-key.pem
```

#### Verify With an immudb Anchor, Fail Closed if Absent

```bash
mpe verify record \
  --public-key notary-public-key.pem \
  --immudb-public-key immudb-public-key.pem \
  --require-anchor immudb \
  --bundle bundle.json
```

#### Verify With an S3 Anchor Required

S3's `content_sha256` binding needs no out-of-band key — it is a pure function of the bundle's own
`signed_root` — so `--require-anchor s3` never takes a corresponding public-key flag:

```bash
mpe verify record \
  --public-key notary-public-key.pem \
  --require-anchor s3 \
  --bundle bundle.json
```

### Where to Obtain Each Key

| Key | Source |
|-----|--------|
| `--public-key` | The notary's Ed25519/ECDSA public key, published by the deployment (e.g. `GET /api/v1/notary/public-key`) or distributed by the operator out-of-band. |
| `--immudb-public-key` | The immudb server operator's signing key — obtain from the server operator, never from a bundle or a live immudb connection. |

Fetch each key once, store it alongside the others (e.g. in a customer audit repository), and
reuse that pinned copy for every future verification — re-fetching per verification reintroduces
the live-server trust this command is designed to avoid.

### Exit Codes

| Code | Description |
|------|-------------|
| 0 | All records `VERIFIED`, result set `COMPLETE` |
| 1 | Tampering detected, an anchor's proof was invalid (when its public-key flag was supplied), a `--require-anchor` type was absent from the bundle or present without its public-key flag, the root hash-chain link failed to verify, the bundle's `retention_policy.mode` could not be parsed, or (set bundles only) records are neither all `VERIFIED` nor all `UNVERIFIED-NOT-SEALED` |
| 2 | `UNVERIFIED-NOT-SEALED` — *every* record in the bundle is a pre-enablement record, or the audit-integrity feature was disabled the whole time the bundle's records were written. A set bundle mixing `VERIFIED` and `UNVERIFIED-NOT-SEALED` records is exit **1**, not 2. |
| 3 | Bundle parse error, key load error, or invalid flag value |

An unrecognized flag, or a flag missing its required value, never reaches the checks above — the
underlying CLI framework exits **1** directly, before `verify record`'s own exit-code convention
runs at all.

### Output

`verify record` prints a human-readable line per record, the batch root's signature and
chain-continuity status, any anchor verification results, an overall result-set summary, and a
`RESULT:` verdict line that always mirrors the process exit code — the single line to parse or
diff in a script, so a component line further up (e.g. `Result set: complete`) can never look
contradictory next to a non-zero exit. `RESULT:` is the verdict line, not necessarily the *last*
line of output, though: when any anchor is present, an `Anchor verification commands:` block (an
equivalent `immudb-client`/`mc stat` command for independent cross-checking) is printed
immediately after it. A script that keys off the exit code should match the `RESULT:` line
itself, not assume it is the final line (`tail -1`).

```
Record <bundle-record>: VERIFIED (leaf hash and signature verified; merkle=OK, root=Ab3f9c2e1d0a…)
Root signature: OK
Chain continuity: OK — chain link verified
Result set: complete
RESULT: OK (exit 0)
```

`Result set: complete` means only that **every record in this bundle verified** — it is a
per-bundle roll-up of the checks above, not a completeness claim in the `verify completeness`
sense below. A static bundle can never prove a record wasn't silently deleted from outside its own
contents; only `verify completeness` against the live deployment establishes that.

#### Output Lines

The happy-path example above is not the only shape of output. The complete set of lines `verify
record` can print, and whether each one affects the exit code:

| Line | Meaning | Affects exit code? |
|------|---------|---------------------|
| `Record <id>: VERIFIED (...)` | Per-record integrity and Merkle inclusion passed | Contributes to the overall verdict |
| `Record <id>: TAMPERED (...)` | Per-record signature, leaf hash, or Merkle proof failed | Yes — forces exit 1 |
| `Record <id>: UNVERIFIED-NOT-SEALED (...)` | No integrity data — a pre-enablement record, or the feature was disabled when it was written | Contributes to the overall verdict (see Exit Codes) |
| `Root signature: OK` | Batch root signature verified | — |
| `Root signature: TAMPERED (signature verification failed)` | Batch root signature is invalid | Yes — forces exit 1 |
| `Chain continuity: OK — chain link verified` | Predecessor root was embedded and its signature and hash link both verified | — |
| `Chain continuity: CAVEAT — <detail>` | Genesis root, or a claimed predecessor was not embedded in this bundle (a full chain walk is the in-service job) | No — non-fatal |
| `Chain continuity: FAIL — <detail>` | Predecessor's own signature was invalid, or `prev_root_hash_b64` did not match | Yes — forces exit 1 |
| `Retention floor: WARNING — record seq below authorized floor` | The record's `notary_ts_to` is older than the authorized retention floor | **No** — advisory only; exit code is unaffected |
| `Retention floor: ERROR — could not parse retention_policy` | `retention_policy.mode` is not `retain-all`, `relative`, or absent | Yes — forces exit 1 |
| `immudb anchor: VERIFIED / FAILED / SKIPPED — <detail>` | See the immudb behavior table under [Step 7](/reference/verification-bundle-schema#step-7--optional-immudb-anchor-verification-fail-closed) | `FAILED` forces exit 1; `SKIPPED` does not |
| `s3 anchor: VERIFIED / FAILED / SKIPPED — <detail>` | See the s3 behavior table under [Step 8](/reference/verification-bundle-schema#step-8--optional-s3-worm-anchor-content-binding-fail-closed) | `FAILED` forces exit 1; `SKIPPED` does not |
| `Result set: complete` / `incomplete` | Roll-up: `complete` only when every record verified and nothing above failed | Mirrors, but does not itself set, the exit code |
| `RESULT: OK (exit 0)` / `RESULT: UNVERIFIED (exit 2)` / `RESULT: FAILED (exit N)` | The single verdict line to parse in scripts | Always equals `result.ExitCode` |
| `Anchor verification commands: ...` | Independent cross-check commands, printed **after** `RESULT:` | — |

For a set (multi-record) bundle, offline verification can confirm everything the bundle itself
contains is internally consistent — per-record integrity, Merkle inclusion, root signatures, and
chain continuity across `signed_roots[]` — but it has no signed signal ruling out that further
records were dropped past the bundle's own tail, or deleted from an interior position the bundle
never claimed to cover in the first place: a static, offline artifact cannot prove a negative about
what else exists. Corroborating completeness requires `verify completeness` against the live
deployment, not this bundle.

## verify completeness

Run the online, anchor-authoritative completeness scan across a notary_ts window.

### Description

`verify completeness` proves the negative `verify record` cannot: that nothing was silently
deleted from a notary_ts window. It dials the anchor backend directly (S3 or immudb — whichever
tier the deployment is configured with) and calls a running iam-lite deployment's read-only NDJSON
notary proxy (`/api/v1/notary/leaves`, `/api/v1/notary/record-existence`) for the
ElasticSearch-backed steps. Every field it reads is self-authenticating — hash- or
signature-checked downstream — so a compromised iam-lite service can only omit evidence, never
forge it; omission is exactly what this scan is built to catch.

Per requested partition, for the given `[from-ts, to-ts)` window, the scan:

1. Enumerates every anchored root directly from the anchor backend.
2. Verifies each root's signature and its chain link to its predecessor.
3. Verifies each root's own anchor-inclusion proof at the anchor's native depth (immudb's
   ALH-binding/`entry_hash`/state-signature check, or S3's WORM/checksum binding).
4. Verifies offset contiguity across the enumerated roots, with a degenerate-range exception for
   heartbeat roots (`tree_size == 0`) that re-assert the predecessor's `to_seq` rather than
   advancing it.
5. Verifies the tail against the anchor's own head pointer — an anchor ahead of the last
   enumerated root means roots were withheld.
6. Verifies `partition_count` coverage across every requested partition (idle vs. a
   whole-partition drop).
7. Verifies batch density: recomputes each non-heartbeat batch's Merkle root from its leaf list and
   requires equality with the anchor-fetched root hash.
8. Verifies record existence for every leaf, retention-floor-aware — a record legitimately retired
   by ILM must not read as tamper evidence.

A discrepancy at step 7 or 8 pinpoints the exact `(partition, offset, leaf_index, root_id)` and is
written to a portable **counter-example bundle** — a `record`-kind offline bundle, independently
re-verifiable via `mpe verify record`.

### Options

#### Window and Trust Root

| Option | Alias | Description | Required |
|--------|-------|-------------|----------|
| `--partitions` | `-p` | Comma-separated partition indices and/or inclusive ranges to scan, e.g. `0,2,4-6` | Yes |
| `--from-ts` | | Inclusive lower bound of the notary_ts scan window, epoch milliseconds | Yes |
| `--to-ts` | | Exclusive upper bound of the notary_ts scan window, epoch milliseconds | Yes |
| `--notary-public-key` | `-k` | Path to PEM-encoded notary signing public key | Yes |
| `--trusted-now` | `-n` | Epoch milliseconds for "now" (default: current time). Accepted for consistency with `verify record`, but this scan currently delegates step 8's retention-floor decision entirely to the notary proxy's own `authorized_absent` response — this flag has no effect on that decision today. | No |

#### Anchor Backend

| Option | Alias | Description | Required |
|--------|-------|-------------|----------|
| `--anchor-type` | | Anchor backend to scan directly: `s3` or `immudb` | Yes |
| `--s3-bucket` | | S3 bucket the anchor store writes to | When `--anchor-type=s3` |
| `--s3-region` | | S3 region | When `--s3-endpoint` is not set |
| `--s3-endpoint` | | S3-compatible endpoint override (e.g. MinIO); empty selects the standard AWS endpoint | No |
| `--s3-access-key-id` | | S3 access key ID | When `--anchor-type=s3` |
| `--s3-secret-access-key` | | S3 secret access key | When `--anchor-type=s3` |
| `--s3-path-style` | | Use path-style S3 addressing (required by most S3-compatible endpoints, e.g. MinIO) | No |
| `--s3-ca-cert` | | PEM CA bundle to pin TLS trust for the S3 endpoint; empty uses the system trust store | No |
| `--immudb-host` | | immudb REST gateway host | When `--anchor-type=immudb` |
| `--immudb-port` | | immudb REST gateway port | When `--anchor-type=immudb` |
| `--immudb-database` | | immudb database name | When `--anchor-type=immudb` |
| `--immudb-username` | | immudb username | When `--anchor-type=immudb` |
| `--immudb-password` | | immudb password | When `--anchor-type=immudb` |
| `--immudb-public-key` | `-i` | Path to PEM-encoded immudb server public key, the anchor's own out-of-band trust root | When `--anchor-type=immudb` |
| `--immudb-ca-cert` | | PEM CA bundle to pin TLS trust for immudb; empty plus `--immudb-allow-insecure` selects plain HTTP | No |
| `--immudb-allow-insecure` | | Allow a plaintext HTTP connection to immudb (development only) | No |

#### Notary Proxy and Output

| Option | Alias | Description | Required |
|--------|-------|-------------|----------|
| `--notary-url` | | Base URL of the iam-lite deployment's notary proxy endpoints, e.g. `https://iam-lite.internal` | Yes |
| `--notary-auth-header` | | Authorization header value sent on every notary-proxy request, e.g. `Bearer <token>` | No |
| `--concurrency` | | How many partitions to scan concurrently (default: number of partitions requested) | No |
| `--record-existence-batch-size` | | How many record ids to send per record-existence request (default: 500) | No |
| `--output` | `-o` | Path to write a counter-example bundle if a discrepancy is found (default: `completeness-counterexample.json`) | No |

Every PEM key file (`--notary-public-key`, `--immudb-public-key`) is capped at 256 MiB; an
oversized file is rejected rather than truncated. Only the explicit `--s3-access-key-id`/
`--s3-secret-access-key` flags are used for S3 credentials — the standard AWS environment/profile
credential chain is deliberately **not** consulted, so `$AWS_ACCESS_KEY_ID` in the examples below is
just a shell convention for passing the value, not an implicit fallback.

### Examples

#### Scan One Partition Against S3

```bash
mpe verify completeness \
  --partitions 0 --from-ts 1735689600000 --to-ts 1735776000000 \
  --notary-public-key notary-public-key.pem \
  --anchor-type s3 --s3-bucket manetu-notary-anchor --s3-region us-east-1 \
  --s3-access-key-id "$AWS_ACCESS_KEY_ID" --s3-secret-access-key "$AWS_SECRET_ACCESS_KEY" \
  --notary-url https://iam-lite.internal
```

#### Scan Several Partitions Against immudb, With a Bearer Token

```bash
mpe verify completeness \
  --partitions 0-3 --from-ts 1735689600000 --to-ts 1735776000000 \
  --notary-public-key notary-public-key.pem \
  --anchor-type immudb --immudb-host immudb.internal --immudb-port 8080 \
  --immudb-database defaultdb --immudb-username notary --immudb-password "$IMMUDB_PASSWORD" \
  --immudb-public-key immudb-public-key.pem \
  --notary-url https://iam-lite.internal --notary-auth-header "Bearer $TOKEN"
```

### Exit Codes

| Code | Description |
|------|-------------|
| 0 | Clean scan: every enumerated root, batch, and record checked out |
| 2 | One or more discrepancies found; see the pinpointed finding(s) and, when a pinpoint is available, the written counter-example bundle |
| 3 | Configuration error, key load error, or a scan infrastructure failure (never produced for a genuine tamper finding — those are always exit 2) |

An unrecognized flag, or a flag missing its required value, never reaches the checks above — the
underlying CLI framework exits **1** directly, before `verify completeness`'s own exit-code
convention runs at all.

### Output

`verify completeness` prints the anchor tier, a partition-by-partition tally of roots walked and
leaves censused, and — on a discrepancy — every finding with its kind, partition, root, and (when
available) its exact `(offset, leaf_index)` pinpoint, ending in the same single, unambiguous
`RESULT:` line convention `verify record` uses.

```
Anchor tier: s3:provider-trusted-worm
Partitions walked: 1, roots walked: 42, leaves censused: 4096
  partition 0: 42 roots, 4096 leaves
RESULT: OK (exit 0)
```

A partition line is suffixed ` (idle)` when that partition had zero roots in the requested window
but the anchor's own head pointer confirms it is legitimately idle rather than dropped (step 6).

When step 7 (batch density) or step 8 (record existence) surfaces a finding, `verify completeness`
prints its `RESULT:` line, then writes a counter-example bundle to `--output` (default
`completeness-counterexample.json`) and reports where it was written — re-verify it directly with
`mpe verify record`:

```
Findings:
  [record-existence] partition=0, root_id=abc123…, offset=104, leaf_index=104, record_id=rec-9f2c: record is absent from accesslog but still inside the retention window
RESULT: FAILED (exit 2)
Counter-example bundle written to completeness-counterexample.json (re-verify with: mpe verify record --public-key <notary-public-key.pem> --bundle completeness-counterexample.json)
```

Re-verifying the written counter-example with `mpe verify record` should exit **2**
(`UNVERIFIED-NOT-SEALED` — absence proven; the bundle deliberately carries no record data) for a
`record-existence` finding, or **1** (`TAMPERED` — inclusion unprovable) for a `batch-density`
finding. It should never exit 0: a counter-example bundle exists precisely because something failed
to verify, so a clean re-verify result would indicate a bug, not confirmation. If the
counter-example itself cannot be built or written (e.g. an unwritable `--output` path), a
`Warning:` line is printed to stderr instead — the scan's own `RESULT:`/exit code is unaffected,
since the discrepancy was still found and reported.

The earlier structural findings (root signature, chain, anchor-proof, contiguity, tail-truncation,
partition coverage) are reported the same way but have no single root or record to pin a
counter-example bundle to.
