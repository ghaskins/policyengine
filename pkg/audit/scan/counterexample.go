//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"encoding/json"
	"fmt"
	"os"
)

const bundleMetaType = "manetu-audit-verification-bundle"

// bundleSchemaVersion mirrors mpe-iam-lite's notary/bundle.clj schema-version
// -- a counter-example bundle is just a record-kind offline bundle, so it
// must declare the same schema_version a real bundle assembler would, or
// `mpe verify record` rejects it at the meta precondition gate before any
// content is examined.
const bundleSchemaVersion = "2.0"

// RecordEnvelope is the record-kind bundle's "record" sub-document -- the
// same shape record.record_pb_b64/integrity{...} the GraphQL bundle
// assembler produces. Leave the whole *RecordEnvelope nil to build a
// counter-example proving a record's ABSENCE (scan step 8: the record does
// not exist in accesslog at all) -- pkg/audit/verify treats a bundle with no
// "record" data as UNVERIFIED-NOT-SEALED (exit 2), which is exactly the
// correct, honest verdict for "this record is genuinely missing," not a
// crash or parse rejection.
type RecordEnvelope struct {
	RecordPBB64  string
	LeafHashB64  string
	SignatureB64 string
	KeyID        string
	SigAlg       string
}

// BuildCounterExampleBundle assembles a portable, record-kind offline bundle
// pinpointing finding -- s-3vlq decision 7. root is the signed root the
// finding was discovered against; prevRoot, when non-nil, is root's
// predecessor (embedded so `mpe verify record`'s Step 5 can recursively
// re-verify the chain link, not just trust root's own prev_root_hash_b64
// claim); anchorRefs is the anchor-tier proof material from
// AnchorClient.AnchorRef; record is nil for a "record-existence" finding
// (proving absence) or populated for a "batch-density" finding where the
// record itself is present but its batch inclusion could not be trusted.
//
// No merkle_proof is ever included: for a "record-existence" finding there
// is no record to prove inclusion for, and for a "batch-density" finding the
// leaf-index's own leaf_index/audit_path is exactly the untrusted material
// the finding is about -- offering it would misrepresent untrustworthy data
// as a proof. Omitting it is not a gap: pkg/audit/verify correctly reports
// the resulting bundle as UNVERIFIED-NOT-SEALED (no record) or TAMPERED
// (record present, inclusion unprovable) -- both honest, re-verifiable
// verdicts for a counter-example, never a false VERIFIED.
func BuildCounterExampleBundle(finding Finding, root EnumeratedRoot, prevRoot *EnumeratedRoot, anchorRefs map[string]interface{}, record *RecordEnvelope) (map[string]interface{}, error) {
	if finding.Kind != "batch-density" && finding.Kind != "record-existence" {
		return nil, fmt.Errorf("scan: build-counter-example-bundle: finding kind %q has no (partition, offset, leaf_index, root_id) pinpoint to build a bundle from", finding.Kind)
	}
	if root.RootID != finding.RootID {
		return nil, fmt.Errorf("scan: build-counter-example-bundle: root %q does not match finding's root_id %q", root.RootID, finding.RootID)
	}

	bundle := map[string]interface{}{
		"meta": map[string]interface{}{
			"type":           bundleMetaType,
			"schema_version": bundleSchemaVersion,
			"bundle_kind":    "record",
		},
		"root_id":     root.RootID,
		"signed_root": root.Payload,
		// "record" must be present as a KEY even when there is no record to
		// embed (proving absence): pkg/audit/verify's single-vs-set routing
		// checks top-level key presence, not value nilness ("A bundle with a
		// top-level record key, even if null, is treated as a single-record
		// bundle" -- verification-bundle-schema.md). Omitting the key
		// entirely would make the bundle look like an ambiguous/malformed
		// "set" bundle instead.
		"record": nil,
	}
	if anchorRefs != nil {
		bundle["anchor_refs"] = anchorRefs
	}
	if prevRoot != nil {
		if prevID, ok := getString(root.Payload, "prev_root_id"); ok && prevID == prevRoot.RootID {
			bundle["prev_signed_root"] = prevRoot.Payload
		}
	}
	if record != nil {
		bundle["record"] = map[string]interface{}{
			"record_pb_b64": record.RecordPBB64,
			"integrity": map[string]interface{}{
				"leaf_hash_b64": record.LeafHashB64,
				"signature_b64": record.SignatureB64,
				"key_id":        record.KeyID,
				"sig_alg":       record.SigAlg,
			},
		}
	}
	return bundle, nil
}

// WriteCounterExampleBundle writes bundle as indented JSON to path.
func WriteCounterExampleBundle(path string, bundle map[string]interface{}) error {
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("scan: write-counter-example-bundle: encode failed: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("scan: write-counter-example-bundle: write failed: %w", err)
	}
	return nil
}
