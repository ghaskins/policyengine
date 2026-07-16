---
sidebar_position: 5
---

# Verification Bundle Schema

Complete reference for the **verification bundle** — the self-contained artifact needed to independently audit a tamper-evident access-log record. <FeatureChip variant="premium" />

A verification bundle embeds everything a verifier needs: the raw protobuf record, its per-record signature, a Merkle inclusion proof, the signed batch root, and a reference to the external anchor (immudb or S3/MinIO — a deployment configures exactly one anchor backend, never both).

**No live PolicyEngine service is required to verify a bundle** — that is the entire point of the format. Once you have a bundle and the out-of-band trust root, verification is fully offline.

Audit-log notarization (batch Merkle sealing, external anchoring, and this bundle format) is a <FeatureChip variant="premium" /> capability built on the [ElasticSearch audit integration](/concepts/audit).

## Obtaining a Bundle

Bundles are retrieved from a running PolicyEngine deployment through the GraphQL API — there is no REST endpoint for bundle retrieval.

```graphql
# Single-record bundle
query {
  inclusion_proof(record_id: "550e8400-e29b-41d4-a716-446655440000") {
    bundle
  }
}

# Multi-record ("set") bundle
query {
  verify_result_set(record_ids: ["<id1>", "<id2>", "..."]) {
    bundle
  }
}
```

| Field | Returns |
|-------|---------|
| `inclusion_proof(record_id: String!)` | `{ bundle }` — a single-record bundle |
| `verify_result_set(record_ids: [String!]!)` | `{ bundle }` — a set bundle covering all given IDs |

Both fields return `bundle` as a JSON-encoded string (the schema below). `verify_result_set` accepts a **maximum of 500** record IDs per request; exceeding this limit returns a GraphQL error. Both queries resolve to `null` when audit integrity is not enabled — check the `audit_integrity_enabled` query first.

The `mpe verify record` CLI command performs fully offline verification of a bundle you have already fetched — it is primarily a **verifier**, not a bundle producer. See [Step 7](#step-7--optional-immudb-anchor-verification-fail-closed) (immudb) and [Step 8](#step-8--optional-s3-worm-anchor-content-binding-fail-closed) (S3) below.

`mpe verify completeness` is the one exception: when it finds a discrepancy, it assembles and
writes a **counter-example bundle** pinpointing the exact finding — see [Counter-Example
Bundles](#counter-example-bundles) below.

## Obtaining the Trust Root (public key)

The signing public key must be obtained *out-of-band* — do **not** trust a key that comes exclusively from a live service endpoint.

| Source | How |
|--------|-----|
| Customer audit repository | `<repo>/audit/public-key.pem` |
| Service HTTP (secondary) | `GET /api/v1/notary/public-key` (no auth required; moved from the unversioned `/api/notary/public-key` when the versioned `/api/v1/notary/*` surface was introduced — mpe-iam-lite s-3vlq decision 5) |
| Local export path | `/var/manetu/notary/public-key.pem` (operator-configured) |

## Full JSON Schema

```json
{
  "meta": {
    "type":           "manetu-audit-verification-bundle",
    "schema_version": "2.0",
    "bundle_kind":    "record"
  },
  "root_id":        "<string — this bundle's batch root identifier; the key immudb's HTree anchors this root under>",

  "record": {
    "record_pb_b64": "<base64url — verbatim AccessRecord protobuf bytes>",
    "integrity": {
      "leaf_hash_b64":  "<base64url — SHA-256(record_pb_b64 bytes)>",
      "signature_b64":  "<base64url — signature over leaf_hash_b64 bytes>",
      "key_id":         "<string  — first 16 hex chars of SHA-256(public-key DER)>",
      "sig_alg":        "<string  — 'Ed25519' | 'ECDSA-P256-SHA256'>"
    }
  },

  "merkle_proof": {
    "leaf_index": 42,
    "offset":     1042,
    "audit_path": [
      {"hash_b64": "<base64url>", "side": "left"},
      {"hash_b64": "<base64url>", "side": "right"}
    ]
  },

  "signed_root": {
    "root_hash_b64":      "<base64url — Merkle root of the batch>",
    "tree_size":          1000,
    "partition":          0,
    "partition_count":    4,
    "covered_range":      {"from_seq": 0, "to_seq": 999},
    "prev_root_hash_b64": "<base64url | null — previous batch root hash>",
    "prev_root_id":       "<string | null — previous batch root identifier>",
    "notary_ts_from":     1699999900000,
    "notary_ts_to":       1700000000000,
    "retention_policy":   {"mode": "relative", "P": "P6M"},
    "root_signature_b64": "<base64url — Ed25519 signature over canonical JSON of signed_root payload>",
    "root_key_id":        "<string>"
  },

  "prev_signed_root": {
    "root_hash_b64":      "<base64url — must equal this bundle's signed_root.prev_root_hash_b64>",
    "tree_size":          999,
    "partition":          0,
    "partition_count":    4,
    "covered_range":      {"from_seq": -999, "to_seq": -1},
    "prev_root_hash_b64": "<base64url | null>",
    "prev_root_id":       "<string | null>",
    "notary_ts_from":     1699998900000,
    "notary_ts_to":       1699999000000,
    "retention_policy":   {"mode": "relative", "P": "P6M"},
    "root_signature_b64": "<base64url — verified recursively via Step 4 (VerifyRootSignature)>",
    "root_key_id":        "<string>"
  },

  "anchor_refs": {
    "immudb":  {"state_db":        "defaultdb",
                "tx_id":           12345,
                "entry_hash":      "<base64url — immudb's real HTree leaf over (root_id, value); see Step 7 check 4>",
                "inclusion_proof": ["<base64url — sibling hash>", "..."],
                "tx_nentries":     3,
                "tx_eH":           "<base64url — entries-hash root (HTree root)>",
                "tx_hash":         "<base64url — signed ALH: sha256(tx_id(8BE) || tx_prev_alh(32) || innerHash(32))>",
                "state_signature": "<base64url — signature over (state_db, tx_id, tx_hash)>",
                "tx_ts":           1700000000,
                "tx_version":      1,
                "tx_bl_tx_id":     50,
                "tx_bl_root":      "<base64url — binary-linking tree root>",
                "tx_prev_alh":     "<base64url — previous transaction's ALH>"}
  }
}
```

> A bundle carries **at most one** `anchor_refs` entry: a deployment configures exactly one anchor backend (`immudb` or `s3`), never both. A single-record bundle anchored to S3 instead carries `"anchor_refs": {"s3": {"bucket": "audit-roots", "key": "roots/0/<root_id>.json", "version_id": "xyz", "content_sha256": "<base64 — sha256 of the canonical signable subset of signed_root; see Step 8>"}}`.

> `prev_signed_root` is present only on a **non-genesis single-record bundle** — i.e. when `signed_root.prev_root_id` is non-null. It embeds the **entire predecessor `signed_root` object**, not just its id/hash, so Step 5 can recursively re-verify the predecessor's own signature (Step 4) before trusting the hash link. Omit it entirely for a genesis root (`signed_root.prev_root_id` absent or `null`).

> **Set bundles** replace the top-level `record` / `merkle_proof` / `signed_root` / `root_id` with `records[]`, `signed_roots[]`, and `anchor_refs_by_root{}` (keyed by root-id), and have **no** top-level `prev_signed_root` — chain continuity across roots is instead derived directly from the embedded `signed_roots[]` themselves (see Step 5). Each entry in `records[]` still carries its own `root_id`, naming which entry of `signed_roots{}`/`anchor_refs_by_root{}` that record belongs to — this is not a new field introduced alongside the top-level `root_id` above; set bundles have always keyed their per-root maps this way. `meta.bundle_kind` is `"set"` for a set bundle (`"record"` for a single-record bundle) — see the note on `meta` below. No bundle kind carries a `completeness` claim: detecting a record *deleted* from the notary's own store, as opposed to modified, isn't something a static, offline artifact can reliably prove, so that check is moving to an online, anchor-authoritative scan instead of a bundle field.

> **`meta`** is a required, **unsigned** envelope carried outside all signed/hashed material — it is not part of `signed_root`'s signable fields, `entry_hash`, or any Merkle computation, and must never be trusted as a substitute for cryptographic verification. Its sole purpose is a fail-fast precondition check, performed before any other verification step: `meta.type` must equal `"manetu-audit-verification-bundle"` (rejecting a wrong kind of input — a PEM, an anchor object, an unrelated JSON document — with a clear error instead of a downstream parse failure), `meta.schema_version` ("MAJOR.MINOR") must have a MAJOR this verifier supports (a greater MAJOR is refused; a greater MINOR is accepted, since MINOR bumps are additive-only by policy), and `meta.bundle_kind` must agree with the bundle's actual structure (`record` vs. `records`/`signed_roots` key presence) — a self-consistency cross-check, not the routing authority, since `meta` is unsigned and the structural key presence remains authoritative for single-vs-set dispatch. A bundle missing `meta`, or failing any of these checks, is rejected outright (`mpe verify record` exit code 3) before any signature, hash, or proof is examined.

## Verification Algorithm (Step-by-Step)

A third-party verifier MUST perform all steps. Any single failure invalidates the bundle. This is the seed algorithm for the `mpe verify record` Go implementation; the reference code below is Python for clarity but every step is language-agnostic.

### Step 1 — Decode and hash the record

```python
import hashlib, base64

record_pb_bytes = base64.urlsafe_b64decode(bundle["record"]["record_pb_b64"] + "==")
leaf_hash       = hashlib.sha256(record_pb_bytes).digest()

assert base64.urlsafe_b64encode(leaf_hash).rstrip(b"=").decode() \
       == bundle["record"]["integrity"]["leaf_hash_b64"], \
       "leaf_hash mismatch"
```

### Step 2 — Verify the per-record signature

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

with open("public-key.pem", "rb") as f:
    pub_key = load_pem_public_key(f.read())

sig = base64.urlsafe_b64decode(bundle["record"]["integrity"]["signature_b64"] + "==")
pub_key.verify(sig, leaf_hash)   # raises InvalidSignature on failure
```

`sig_alg` is always `Ed25519`; ECDSA-P256-SHA256 is accepted by the verifier but no key backend currently emits it.

### Step 3 — Verify the Merkle inclusion proof

Each tree leaf is **not** the bare `leaf_hash` from Step 1 — it is a **positioned leaf preimage** that binds the record's tree position (`partition`, `offset`, `index`, `notary_ts`) to its content (`leaf_hash`) (Design D1, mpe-iam-lite s-2lxx decision 4). The per-record signature (Step 2) still covers `leaf_hash` alone — position rides the *signed root* via the tree, not the per-record signature. Binding position into the leaf means a deleted/substituted/re-ordered record fails inclusion against the signed root, even though its own content hash and signature still verify on their own.

```python
def positioned_leaf_preimage(partition, offset, index, notary_ts, leaf_hash):
    # Canonical JSON: sorted keys, no whitespace — same encoder as Step 4.
    signable = {
        "partition": partition,
        "offset": offset,
        "index": index,
        "notary_ts": notary_ts,
        "content_hash_b64": base64.urlsafe_b64encode(leaf_hash).rstrip(b"=").decode(),
    }
    payload = json.dumps(signable, sort_keys=True, separators=(',', ':')).encode("utf-8")
    return hashlib.sha256(payload).digest()

def rfc6962_leaf_hash(leaf_hash):
    # RFC 6962 §2.1: leaf domain separator
    return hashlib.sha256(b'\x00' + leaf_hash).digest()

def node_hash(left, right):
    # RFC 6962 §2.1: internal-node domain separator
    return hashlib.sha256(b'\x01' + left + right).digest()

def verify_proof(leaf_hash, proof, root_hash):
    cur = rfc6962_leaf_hash(leaf_hash)
    for step in proof["audit_path"]:
        sibling = base64.urlsafe_b64decode(step["hash_b64"] + "==")
        if step["side"] == "right":
            cur = node_hash(cur, sibling)
        else:
            cur = node_hash(sibling, cur)
    expected = base64.urlsafe_b64decode(root_hash + "==")
    assert cur == expected, "Merkle proof invalid"

sr = bundle["signed_root"]
mp = bundle["merkle_proof"]
positioned = positioned_leaf_preimage(
    sr["partition"], mp["offset"], mp["leaf_index"], sr["notary_ts_to"], leaf_hash
)

verify_proof(
    positioned,
    bundle["merkle_proof"],
    bundle["signed_root"]["root_hash_b64"]
)
```

Tree construction rule: when a level has an odd number of nodes, the last node is promoted to the next level unchanged (RFC 6962 odd-count handling — no duplicate-last-leaf padding).

### Step 4 — Verify the signed batch root

The signed payload is the **canonical JSON** of a fixed 10-field **positive allowlist** of `signed_root` — not "everything except the signature fields." Reconstruct it by selecting those 10 fields, recursively sorted string keys, no whitespace. This is reproducible in any language.

Do **not** reconstruct the signable payload by stripping `root_signature_b64`/`root_key_id` from the map: the runtime signed root carries a third, non-signature field, `root_pub_key_b64` (the signer's public key — advisory metadata, never covered by the signature). A bundle's `signed_root` happens to omit `root_pub_key_b64` already — it is stripped before the root is written into the bundle, so a bundle's `signed_root` carries only the 10 signable fields plus the 2 signature fields (12 total) — but a verifier reconstructing the payload from an anchor-fetched root (which still carries all 13 fields) must use the positive allowlist below, or a leftover `root_pub_key_b64` will produce a different canonical JSON than what was actually signed and the signature check will spuriously fail.

```python
import json, base64

sr       = bundle["signed_root"]
root_sig = base64.urlsafe_b64decode(sr["root_signature_b64"] + "==")

# Build the signable object: the fixed positive allowlist of signed fields
# (do NOT derive this by stripping signature fields — see note above)
SIGNABLE_FIELDS = {
    "root_hash_b64", "tree_size", "partition", "partition_count", "covered_range",
    "prev_root_hash_b64", "prev_root_id", "notary_ts_from", "notary_ts_to",
    "retention_policy",
}
signable = {k: v for k, v in sr.items() if k in SIGNABLE_FIELDS}

# Canonical JSON: sorted keys, no whitespace
payload_bytes = json.dumps(signable, sort_keys=True, separators=(',', ':')).encode("utf-8")

pub_key.verify(root_sig, payload_bytes)   # raises InvalidSignature on failure
```

The fields present in the signable object are:
`covered_range`, `notary_ts_from`, `notary_ts_to`, `partition`, `partition_count`, `prev_root_hash_b64`, `prev_root_id`, `retention_policy`, `root_hash_b64`, `tree_size` (sorted alphabetically as they appear in the canonical JSON).

#### Canonical JSON conformance rules

The reference Python above (`json.dumps(sort_keys=True, separators=(',', ':'))`) matches the
notary's actual signer byte-for-byte for every field this schema defines, with three exceptions an
independent implementation must replicate to avoid spurious signature-verification failures on
legitimately-signed data:

- **U+007F (DEL) is left unescaped.** Python's `ensure_ascii=True` (the default assumed above)
  escapes DEL as ``; the notary's Jackson-based canonicalizer does not, so `mpe verify
  record`'s Go implementation matches Jackson and also leaves it raw. A field genuinely containing
  a literal DEL byte will fail to verify against a canonicalizer that escapes it.
- **Numbers must be integral and fit a signed 64-bit integer.** Non-integral values (a decimal
  point or exponent notation) and integers outside the signed `int64` range are rejected outright
  rather than canonicalized, matching the notary's own numeric-type constraint.
- **Strings must be well-formed UTF-8.** A canonicalizer that would otherwise substitute U+FFFD for
  invalid byte sequences must instead reject the input — two distinct malformed inputs must never
  silently canonicalize to the same bytes.

### Step 5 — Verify root-chain continuity

Confirm that `signed_root` links to its predecessor, forming a tamper-evident chain of batch roots:

- If `signed_root.prev_root_id` is absent or `null`, this is a genesis root — there is no predecessor to verify.
- If a predecessor root is not embedded in the bundle as the top-level `prev_signed_root` field, the link cannot be fully walked offline; this is a caveat, not a failure — full-chain walking is the in-service job. When present, `prev_signed_root` is the **entire predecessor `signed_root` object**, not just its id/hash (see the Full JSON Schema above).
- Otherwise, verify the predecessor's own root signature (Step 4, applied recursively) and confirm `signed_root.prev_root_hash_b64` matches the predecessor's `root_hash_b64`. Either a bad predecessor signature or a hash mismatch means the chain link is broken — **fail closed**.

```python
prev_signed_root = bundle.get("prev_signed_root")   # entire predecessor signed_root object, or absent

prev_root_id = signed_root.get("prev_root_id")
if prev_root_id is None:
    result = "OK (genesis root)"
elif prev_signed_root is None:
    result = "CAVEAT (predecessor not embedded)"
elif not verify_root_signature(prev_signed_root, pub_key):
    result = "FAILED (predecessor root signature invalid)"
elif signed_root["prev_root_hash_b64"] != prev_signed_root["root_hash_b64"]:
    result = "FAILED (prev_root_hash_b64 mismatch: chain link broken)"
else:
    result = "OK (chain link verified)"
```

### Step 6 — Evaluate the retention floor

Determine the authorized retention floor and confirm this record's absence (if applicable) is expected ILM deletion rather than tampering:

- `retention_policy.mode == "retain-all"` (or `retention_policy` wholly absent): floor is `0` — every record must be present.
- `retention_policy.mode == "relative"`: floor is `trusted_now_ms - ParseDuration(retention_policy.P)` (ISO 8601 duration, e.g. `"P6M"`). Records in a root whose `notary_ts_to < floor` are **authorized-absent** — the root's own seal time (`notary_ts_to`, the field that plays this role since `timestamp_ms` was retired) falls before the authorized floor, so the record was legitimately dropped by ILM and its absence is not a tamper signal.
- Any other `mode` value is a parse error and **fails closed** — never silently treated as `retain-all`.

`trusted_now_ms` is supplied out-of-band (e.g. `mpe verify record --trusted-now <epoch-ms>`); it must not be read from the bundle itself.

```python
def authorized_floor(retention_policy, trusted_now_ms):
    mode = retention_policy.get("mode", "retain-all") if retention_policy else "retain-all"
    if mode == "retain-all":
        return 0
    if mode == "relative":
        return trusted_now_ms - parse_iso8601_duration(retention_policy["P"])
    raise ValueError(f"unknown retention-policy mode: {mode!r}")
```

### Step 7 — Optional immudb anchor verification (fail-closed)

If `anchor_refs.immudb` is present, `mpe verify record --immudb-public-key <key.pem>` cryptographically validates it against a pinned immudb server public key (out-of-band trust root — never read from the bundle):

```bash
mpe verify record --public-key notary-public-key.pem \
           --immudb-public-key immudb-server-public-key.pem \
           --bundle bundle.json
```

immudb anchoring is not a single inclusion check — it is four independent sub-proofs, all of which must pass:

1. **HTree inclusion proof** — `entry_hash` (the record's leaf digest) is walked up the bottom-up sibling audit path in `inclusion_proof` and must recompute to `tx_eH`, the entries-hash root of the transaction. An empty `inclusion_proof` is only valid when `tx_nentries == 1` (the leaf IS the root); otherwise it is treated as a stripped proof and fails closed.
2. **Signed state verification** — `tx_hash` is verified as immudb's signed `ImmutableState` over the payload `[len(state_db)(4BE)][state_db bytes][tx_id(8BE)][tx_hash bytes]`, using the pinned immudb public key. This proves *some* state was genuinely signed by the immudb server, but not yet that it corresponds to this record.
3. **ALH binding** — closes the gap left by (2): `tx_hash` must itself be immudb's Accumulator Linear Hash (ALH), recomputed as `sha256(tx_id(8BE) || tx_prev_alh(32) || innerHash(32))` where `innerHash` folds in `tx_ts`, `tx_version`, `tx_nentries`, `tx_eH`, `tx_bl_tx_id`, and `tx_bl_root`. This proves the signed state commits to *this* transaction's `tx_eH`, so a fabricated inclusion proof cannot be paired with a genuine but unrelated signed state.
4. **Entry-hash binding** — checks (1)-(3) prove a genuine, internally-consistent immudb entry exists and is signed by the pinned server key, but nothing yet ties it to *this* bundle. `entry_hash` is immudb's real HTree leaf over the `(root_id, value)` pair the notary commits to the HTree, independently recomputed from this bundle's own trusted content and compared against the asserted value, rather than trusted as asserted (byte-verified against codenotary/immudb 1.11.0):

   ```
   value_bytes  = CanonicalJSONBytes(selectKeys(signed_root, SIGNABLE_FIELDS))   # same allowlist as Step 4
   key          = b"\x00" + root_id.encode()                                    # 0x00-prefixed store key
   value_hash   = sha256(b"\x00" + value_bytes)
   inner        = sha256(uint16_be(0) || uint16_be(len(key)) || key || value_hash)   # mdLen=0: plain KV Set, no metadata
   expected     = sha256(b"\x00" + inner)
   require expected == entry_hash
   ```

   `root_id` is this bundle's own batch root identifier (the top-level `root_id` field on a single-record bundle; the `signed_roots`/`anchor_refs_by_root` map key for the root a record belongs to, on a set bundle). `entry_hash` is the value genuinely carried through immudb's HTree inclusion proof and signed ALH, so a forged or substituted `root_id`/`signed_root` pair changes the recomputed `entry_hash` and fails the comparison — an adversary cannot pair a genuine, unrelated, validly-signed immudb anchor with a forged bundle root. This replaces the previous, now-retired unsigned side-channel field that only detected accidental mismatch, not adversarial substitution. There is no legacy fallback: an anchor written before this check existed fails closed rather than reading as verified.

`state_db` (or its legacy alias `database`) and `tx_id` are also required — they are covered by the state-signature payload in check 2.

Behavior when `anchor_refs.immudb` is present:

| `--immudb-public-key` | All 4 sub-proofs valid | Result |
|-----------------------|-------------------------|--------|
| absent | n/a | SKIPPED (warning logged; root-signature verification governs exit code) |
| present | yes | VERIFIED |
| present | partial (some fields present, some proof material stripped, or `entry_hash` unrecomputable — e.g. `root_id`/`signed_root` unavailable) | FAILED — a partial proof never reads as a full pass |
| present | no | FAILED — **exit code 1** (fail-closed) |

When no `anchor_refs.immudb` is present at all, immudb verification is SKIPPED regardless of `--immudb-public-key`. With `--require-anchor immudb`, an absent anchor — or one present without `--immudb-public-key` — is FAILED instead of SKIPPED.

### Step 8 — Optional S3 WORM anchor content binding (fail-closed)

S3 needs no out-of-band key: `content_sha256` is a pure function of `signed_root`, so the verifier recomputes it and rejects an `s3` ref that does not commit to this bundle's root:

```bash
mpe verify record --public-key notary-public-key.pem --require-anchor s3 --bundle bundle.json
```

This validates that `anchor_refs.s3.content_sha256` equals `base64(sha256(CanonicalJSONBytes(selectKeys(signed_root, SIGNABLE_FIELDS))))` — the same canonical value immudb's `entry_hash` binds to (Step 7 check 4). It does **not** itself reach S3; the live object fetch is manual, below.

Behavior when `anchor_refs.s3` is present:

| `--require-anchor s3` | `content_sha256` present | Binding valid | Result |
|-----------------------|---------------------------|----------------|--------|
| no | no | n/a | SKIPPED (warning; binding cannot be checked) |
| no | yes | yes | VERIFIED |
| no | yes | no | **FAILED — exit code 1** (mismatch is checked even without `--require-anchor`) |
| yes | no | n/a | **FAILED — exit code 1** (fail-closed on a bindingless ref) |
| yes | absent (no `anchor_refs.s3` at all) | n/a | **FAILED — exit code 1** (fail-closed on a stripped anchor) |

Unlike immudb, an `s3` binding mismatch fails **regardless of `--require-anchor`**: no key is needed, so a present binding is always checked.

## Supplementary Manual Verification

Confirming an S3/MinIO anchor against the *live* object store (below) is optional and manual — `mpe verify record` never contacts a network. (Step 8's `content_sha256` check above is already offline and fail-closed; this is an additional, live cross-check.)

### Confirm S3 / MinIO anchoring (optional)

```bash
# Verify the version-pinned object exists and matches:
aws s3api get-object \
  --bucket "$(jq -r .anchor_refs.s3.bucket bundle.json)" \
  --key    "$(jq -r .anchor_refs.s3.key    bundle.json)" \
  --version-id "$(jq -r .anchor_refs.s3.version_id bundle.json)" \
  /tmp/root.json
```

### Set bundles carry no completeness claim

Earlier versions of this schema derived a completeness verdict for set bundles from a per-root
span/density/coverage check (a self-asserted `completeness` block, the union of `signed_roots[*]
.covered_range`, and the disclosed `merkle_proof.leaf_index` values). That machinery is retired: a
static, offline bundle cannot reliably prove a record was *deleted*, as opposed to modified — it can
only attest to what it happens to embed. `mpe verify record` still performs everything the 8 numbered steps
above describe (per-record integrity, Merkle inclusion, root signatures, chain continuity across
`signed_roots[]`, retention floor, and anchor binding) for every record in a set bundle; it no longer
derives or reports a separate completeness verdict. Detecting a record silently dropped from the
notary's own store is moving to an online, anchor-authoritative scan instead.

`mpe verify record`'s printed `Result set: complete` / `incomplete` line (and the `SetComplete`/
`SetIncomplete` status it comes from) is **not** this retired completeness verdict — it is a plain
roll-up of "did every record in this bundle verify," nothing more. Do not read a `complete` result
as ruling out a deleted record; only [`mpe verify completeness`](/reference/cli/verify#verify-completeness)
against the live deployment does that.

### Counter-example bundles

`mpe verify completeness` (see the [CLI reference](/reference/cli/verify#verify-completeness)) is,
alongside the GraphQL bundle-retrieval fields above, the other bundle *producer*: when its batch-density
or record-existence check finds a discrepancy, it assembles and writes a portable, record-kind
offline bundle pinpointing that exact finding, independently re-verifiable with `mpe verify record`.
A counter-example bundle differs from a normal single-record bundle in two ways:

- **`record` is always present as a key, but its value is `null` when the finding proves a record's
  *absence*** (a `record-existence` finding — there is no record to embed). This relies on the
  routing rule stated above: a top-level `record` key, **even if its value is `null`**, still
  routes the bundle to single-record verification. Only a `batch-density` finding — where the
  record itself is present but its batch inclusion could not be trusted — embeds a populated
  `record` object.
- **`merkle_proof` is never included.** For a `record-existence` finding there is no record to
  prove inclusion for; for a `batch-density` finding, the very `leaf_index`/`audit_path` a
  `merkle_proof` would carry is the untrusted material the finding is about, so including one
  would misrepresent unproven data as a proof.

Because of this, re-verifying a counter-example with `mpe verify record` never exits 0: a
`record-existence` counter-example (no `record`) verifies as `UNVERIFIED-NOT-SEALED` (exit 2 —
the honest verdict for "genuinely missing"), and a `batch-density` counter-example (`record`
present, no `merkle_proof`) verifies as `TAMPERED` (exit 1 — inclusion cannot be established). Both
are correct, expected re-verification outcomes for a bundle whose entire purpose is proving a
tamper finding, not clean verification.

## Field Reference

| Field | Type | Notes |
|-------|------|-------|
| `meta.type` | string | Always `"manetu-audit-verification-bundle"`. Unsigned; a precondition check only — see the note above the JSON schema. |
| `meta.schema_version` | string | `"MAJOR.MINOR"`, currently `"2.0"`. A greater MAJOR is refused by `mpe verify record`; a greater MINOR is accepted (additive-only by policy). |
| `meta.bundle_kind` | string | `"record"` or `"set"`. Advisory/self-consistency check only — the bundle's actual key presence (`record` vs. `records`/`signed_roots`) remains the sole routing authority, since `meta` is unsigned. |
| `root_id` | string | Single-record bundles only. This bundle's batch root identifier — the key immudb's HTree anchors `signed_root` under, consumed by Step 7's `entry_hash` recomputation. On set bundles this is **not** a new field: it is already present as the `signed_roots`/`anchor_refs_by_root` map key (and each `records[]` entry's own `root_id`, naming which map entry it belongs to). |
| `record.record_pb_b64` | base64url | Verbatim `AccessRecord` protobuf bytes |
| `record.integrity.leaf_hash_b64` | base64url | SHA-256 of record bytes |
| `record.integrity.signature_b64` | base64url | Signature over leaf hash |
| `record.integrity.key_id` | string | First 16 hex chars of SHA-256(pubkey DER) |
| `record.integrity.sig_alg` | string | `Ed25519` or `ECDSA-P256-SHA256` |
| `merkle_proof.leaf_index` | integer | 0-based position within the batch Merkle tree — also the `index` component of the positioned leaf preimage (see Step 3) |
| `merkle_proof.offset` | integer | This record's Kafka offset within its partition — the `offset` component of the positioned leaf preimage (see Step 3). Combined with `signed_root.partition`/`signed_root.notary_ts_to` and `record.integrity.leaf_hash_b64`, lets a verifier recompute the exact tree leaf |
| `merkle_proof.audit_path` | array | Sibling hashes from leaf to root |
| `signed_root.root_hash_b64` | base64url | Batch Merkle root |
| `signed_root.tree_size` | integer | Number of leaves in the batch. **Authoritative interior-gap indicator**: if `tree_size < to_seq - from_seq + 1`, offsets inside `covered_range` were skipped (e.g. id-dedup drops) even though the endpoints look dense. `covered_range` alone cannot reveal this — always cross-check against `tree_size`. This is a **manual** cross-check today: `mpe verify record` reads `tree_size` only for a per-leaf `leaf_index` bounds sanity check, not as an automated interior-density verdict — see [Set bundles carry no completeness claim](#set-bundles-carry-no-completeness-claim). |
| `signed_root.partition` | integer | Kafka partition ID |
| `signed_root.partition_count` | integer | Total number of partitions in the topic at the time this root was sealed |
| `signed_root.covered_range` | object | `{from_seq, to_seq}` — Kafka offsets spanned by the batch. Endpoints only — does **not** assert every offset in between is present; see `tree_size` for the authoritative gap check. |
| `signed_root.prev_root_hash_b64` | base64url\|null | Previous batch root hash (hash chain link) |
| `signed_root.prev_root_id` | string\|null | Previous batch root identifier (ID chain link) |
| `signed_root.notary_ts_from` | integer | Epoch milliseconds of the earliest record covered by this root |
| `signed_root.notary_ts_to` | integer | Epoch milliseconds of the root's own seal time — plays the role the retired `timestamp_ms` field used to play, including as Step 6's retention-floor input |
| `signed_root.retention_policy` | object | `{mode, P}` — e.g. `{mode:"relative", P:"P6M"}` |
| `signed_root.root_signature_b64` | base64url | Signature over root payload |
| `signed_root.root_key_id` | string | Key identifier of the signing key |
| `prev_signed_root` | object\|absent | Single-record bundles only. The **entire predecessor `signed_root` object** (same shape as `signed_root` above), present only when `signed_root.prev_root_id` is non-null. Consumed by Step 5 (`VerifyRootChain`) to recursively re-verify the predecessor's signature and hash-link it; absent means the chain link falls back to `ChainCaveat` instead of `ChainOK`/`ChainFailed`. |
| `anchor_refs.immudb.state_db` | string | immudb database name (legacy alias: `database`); part of the signed state payload |
| `anchor_refs.immudb.tx_id` | integer | immudb transaction ID; part of the signed state payload and the ALH |
| `anchor_refs.immudb.entry_hash` | base64url | immudb's real HTree leaf over `(root_id, canonical_value_bytes)`: `sha256(0x00 \|\| sha256(uint16(mdLen) \|\| md \|\| uint16(kLen) \|\| (0x00 \|\| root_id) \|\| sha256(0x00 \|\| canonical_value_bytes)))` (byte-verified against immudb 1.11.0; `md` empty for a plain KV Set), where `canonical_value_bytes = CanonicalJSONBytes(selectKeys(signed_root, SIGNABLE_FIELDS))`; independently recomputed from the bundle's own `root_id`/`signed_root` and compared, per Step 7 check 4 |
| `anchor_refs.immudb.inclusion_proof` | array\<base64url\> | HTree bottom-up sibling audit path from `entry_hash` to `tx_eH`; an empty array is only valid when `tx_nentries == 1` |
| `anchor_refs.immudb.tx_nentries` | integer | Number of entries in the transaction; also folded into the ALH inner hash |
| `anchor_refs.immudb.tx_eH` | base64url | Entries-hash (HTree root) for the transaction — the inclusion-proof target and an ALH inner-hash input |
| `anchor_refs.immudb.tx_hash` | base64url | The transaction's signed ALH (Accumulator Linear Hash); verified both as the state-signature payload and by recomputation from the header fields below |
| `anchor_refs.immudb.state_signature` | base64url | immudb server's signature over `(state_db, tx_id, tx_hash)` — the `ImmutableState` signature |
| `anchor_refs.immudb.tx_ts` | integer | Transaction timestamp; ALH inner-hash input |
| `anchor_refs.immudb.tx_version` | integer | Transaction header version (0 or 1; changes the inner-hash layout); ALH inner-hash input |
| `anchor_refs.immudb.tx_bl_tx_id` | integer | Binary-linking tree transaction ID; ALH inner-hash input |
| `anchor_refs.immudb.tx_bl_root` | base64url | Binary-linking tree root hash; ALH inner-hash input |
| `anchor_refs.immudb.tx_prev_alh` | base64url | Previous transaction's ALH; input to this transaction's ALH computation |
| `anchor_refs.s3.bucket` | string | S3-compatible bucket name |
| `anchor_refs.s3.key` | string | Object key of the anchored WORM root, `roots/<partition>/<root_id>.json` |
| `anchor_refs.s3.version_id` | string | Object Lock version ID (WORM proof). A COMPLIANCE lock prevents deleting this version but not layering a *new* version over the key, so reads/fetches must pin this exact version. |
| `anchor_refs.s3.content_sha256` | base64 | `sha256` of the canonical JSON of `select_keys(signed_root, SIGNABLE_FIELDS)` — the offline content binding. Because `signed_root` is already in the bundle, a verifier recomputes this directly and rejects a genuine-but-unrelated s3 object paired with the wrong bundle (mirrors immudb `entry_hash`). See Step 8. |

## Cryptographic Algorithms

| Algorithm | OID | Notes |
|-----------|-----|-------|
| Ed25519 | 1.3.101.112 | Software + PKCS#11 backends |
| ECDSA-P256-SHA256 | 1.2.840.10045.4.3.2 | Accepted by the verifier; no key backend currently emits it |
| SHA-256 | 2.16.840.1.101.3.4.2.1 | Merkle tree + leaf hash |

## Security Notes

- **Do not trust the key from a live endpoint alone.** The service could be compromised. Always cross-check against the customer's audit repository copy.
- `signed_root.prev_root_id` links successive batch roots into a tamper-evident chain; `prev_signed_root`, when embedded, lets a single-record bundle's verifier walk that link offline (Step 5). Gaps in `prev_root_id`, or an absent `prev_signed_root` on a non-genesis root, should be investigated — the latter degrades chain verification to a non-fatal `ChainCaveat` rather than a confirmed `ChainOK`.
- The `anchor_refs` fields are *references*, not proofs in themselves. Always re-fetch and re-verify the referenced objects from their respective systems.

## Base64 Encoding Convention

All integrity fields in this schema use **base64url, no-padding** (RFC 4648 §5, `Base64.getUrlEncoder().withoutPadding()` in Java). This applies to every field annotated `base64url` in the Field Reference table: `record_pb_b64`, `leaf_hash_b64`, `signature_b64`, `root_hash_b64`, `prev_root_hash_b64`, `root_signature_b64`, `merkle_proof.audit_path[*].hash_b64`, and the `anchor_refs.immudb` fields `entry_hash`, `inclusion_proof[*]`, `tx_eH`, `tx_hash`, `state_signature`, `tx_bl_root`, `tx_prev_alh`.

The exception is `anchor_refs.s3.content_sha256`, which is standard base64 with padding.

A conforming offline verifier decodes both variants, normalizing `+/=` ↔ `-_` before decoding, so bundles with either encoding verify correctly. However, **all new writes** must use base64url no-padding — mixing alphabets across fields would cause silent mismatches in any direct string comparison.

## Changelog

| Version | Date | Notes |
|---------|------|-------|
| 2.0 | 2026-08 | Rekor and the builtin anchor tier are retired (mpe-iam-lite deleted the Rekor witness backend and the Sigstore-keyless key backend outright, spec s-9xga); `anchor_refs.minio` is renamed `anchor_refs.s3` and gains an offline, keyless `content_sha256` binding (Step 8) mirroring immudb's `entry_hash`. `merkle_proof` gains a required `offset` field: the Merkle tree's actual leaf preimage is now documented and verified as the *positioned* leaf hash (Design D1) — binding a record's tree position, not just its content hash, into the leaf (Step 3) — closing a gap where a deleted/substituted/re-ordered record could otherwise pass inclusion undetected. The immudb `entry_hash` formula is corrected to immudb's real HTree leaf construction (byte-verified against codenotary/immudb 1.11.0); the previously-documented `sha256(sha256(root_id)\|\|sha256(value))` formula matched no real immudb. |
| 2.0 | 2026-08 | Breaking change (no back-compat shim; a pre-2.0 bundle is refused outright with `mpe verify record` exit code 3). `signed_root.timestamp_ms` is retired, replaced by `signed_root.notary_ts_from`/`signed_root.notary_ts_to` (the latter plays `timestamp_ms`'s former role, including as Step 6's retention-floor input) plus a new `signed_root.partition_count` field — all three are part of the signable allowlist, now 10 fields total (`SIGNABLE_FIELDS`/`SignableRootFields`). The set-bundle `completeness` and `root_chain_context` fields are dropped from `records`/`set` bundles entirely (see the 1.0 row below for the span/density/coverage derivation this retires). |
| 1.0 | 2026-07 | Initial release. Bundle carries a required, unsigned `meta` envelope (`type`, `schema_version`, `bundle_kind`) as a fail-fast precondition gate, checked before any cryptographic verification step; a bundle missing `meta` or failing its checks is rejected outright (`mpe verify record` exit code 3). Covers: per-record leaf-hash and signature verification, RFC 6962 Merkle inclusion, canonical-JSON signed-root verification, root-chain continuity, retention-floor evaluation, immudb anchor binding (proof material cryptographically tied back to this bundle's own `root_id`/`signed_root`, not merely asserted), and set-bundle completeness derivation (span, chain, and interior-density checks). |
| — | — | The set-bundle `completeness` block and its span/density/coverage derivation (checks 3-5 above) are retired: a static, offline artifact cannot reliably prove a record was *deleted*, as opposed to modified. `mpe verify record` still performs every remaining per-record/per-root check for set bundles unchanged; completeness detection is moving to an online, anchor-authoritative scan instead. |

## See Also

- [Audit & Access Records](/concepts/audit) — Conceptual overview of the audit trail this bundle format verifies
- [AccessRecord Schema Reference](/reference/access-record) — The record type embedded in `record.record_pb_b64`
- [CLI Reference](/reference/cli) — `mpe` command reference, including `mpe verify record`
