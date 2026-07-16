//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// immudbNodePrefix is the domain-separator byte immudb's real HTree
// (embedded/htree.NodePrefix) prepends before hashing every internal node
// pair: sha256(immudbNodePrefix || left || right). Byte-verified against
// codenotary/immudb v1.9.7's embedded/htree/htree.go BuildWith/VerifyInclusion.
// entryHash itself already carries the leaf-side domain separator
// (immudb's LeafPrefix) baked in by expectedImmudbEntryHash's outer
// sha256(0x00 || inner) wrap, so only the internal-node fold needs it here.
const immudbNodePrefix = byte(0x01)

// VerifyImmudbInclusion verifies an immudb HTree (entries-hash-tree)
// inclusion proof. entryHash is the 32-byte leaf digest
// sha256(sha256(key)||sha256(value)); inclusionProofB64 is the bottom-up
// sibling audit path (base64, from the immudb API); nentries is the total
// entry count in the transaction (an empty proof is only valid when
// nentries == 1 -- the leaf IS the root); eH is the expected 32-byte
// entries-hash root (tx_eH from the signed state).
//
// The root-id entry is always at index 0 in immudb's setRequest, so every
// proof element is the right sibling at that level: the walk is
// cur = sha256(immudbNodePrefix || cur || sib) for each sib in the audit
// path -- immudb's real internal-node hash always prepends this
// domain-separator byte (embedded/htree.VerifyInclusion), which an earlier
// version of this function omitted, silently computing a different root
// than real immudb for any nentries > 1.
func VerifyImmudbInclusion(entryHash []byte, inclusionProofB64 []string, nentries int64, eH []byte) bool {
	if len(inclusionProofB64) == 0 {
		// An empty proof is only valid for a single-entry tree (leaf IS the
		// root). For nentries > 1 it means the audit path was stripped --
		// fail closed.
		return nentries == 1 && bytes.Equal(entryHash, eH)
	}
	cur := entryHash
	for _, sibB64 := range inclusionProofB64 {
		sib, err := b64Decode(sibB64)
		if err != nil {
			return false
		}
		h := sha256.Sum256(concatBytes([]byte{immudbNodePrefix}, cur, sib))
		cur = h[:]
	}
	return bytes.Equal(cur, eH)
}

// buildImmudbStatePayload constructs the bytes over which immudb's server
// signs the ImmutableState: [4-byte BE uint32 len(db)] [db bytes]
// [8-byte BE uint64 tx-id] [tx-hash bytes].
func buildImmudbStatePayload(db string, txID int64, txHash []byte) ([]byte, error) {
	if txID < 0 {
		return nil, fmt.Errorf("verify: immudb tx_id must be non-negative: %d", txID)
	}
	dbBytes := []byte(db)
	lenBytes, err := intToBEBytes(int64(len(dbBytes)))
	if err != nil {
		return nil, err
	}
	return concatBytes(lenBytes, dbBytes, longToBEBytes(txID), txHash), nil
}

// ImmudbALHFields are the transaction header fields captured alongside an
// immudb inclusion proof, needed to recompute the signed ALH -- see
// ComputeImmudbALH. Metadata may be nil (no metadata, or header version 0
// which has no metadata field).
type ImmudbALHFields struct {
	TxID     int64
	PrevALH  []byte
	TS       int64
	Version  int64
	Nentries int64
	EH       []byte
	BlTxID   int64
	BlRoot   []byte
	Metadata []byte
}

// immudbInnerHash computes immudb's TxHeader.innerHash:
//
//	innerHash = sha256(ts(8BE) || version(2BE) ||
//	                    <v0: nentries(2BE) | v1: mdLen(2BE) || metadata || nentries(4BE)> ||
//	                    eH(32) || blTxID(8BE) || blRoot(32))
func immudbInnerHash(f ImmudbALHFields) ([]byte, error) {
	md := f.Metadata
	if md == nil {
		md = []byte{}
	}
	versionBytes, err := shortToBEBytes(f.Version)
	if err != nil {
		return nil, err
	}
	var mid []byte
	if f.Version == 0 {
		mid, err = shortToBEBytes(f.Nentries)
		if err != nil {
			return nil, err
		}
	} else {
		mdLen, err2 := shortToBEBytes(int64(len(md)))
		if err2 != nil {
			return nil, err2
		}
		nentriesBytes, err3 := intToBEBytes(f.Nentries)
		if err3 != nil {
			return nil, err3
		}
		mid = concatBytes(mdLen, md, nentriesBytes)
	}
	return concatBytes(longToBEBytes(f.TS), versionBytes, mid, f.EH, longToBEBytes(f.BlTxID), f.BlRoot), nil
}

// ComputeImmudbALH recomputes immudb's TxHeader.Alh (Accumulator Linear
// Hash) from the transaction header fields captured alongside the
// inclusion proof:
//
//	Alh = sha256(txID(8BE) || prevAlh(32) || innerHash(32))
//
// This is the exact value the immudb server signs as tx_hash. Recomputing
// and comparing it against the signed tx_hash proves that tx_hash commits
// to this transaction's eH (tx_eH), closing the gap where a fabricated
// inclusion proof could be paired with a genuine but unrelated signed
// state.
func ComputeImmudbALH(f ImmudbALHFields) ([]byte, error) {
	if f.TxID < 0 {
		return nil, fmt.Errorf("verify: immudb tx_id must be non-negative: %d", f.TxID)
	}
	if f.BlTxID < 0 {
		return nil, fmt.Errorf("verify: immudb tx_bl_tx_id must be non-negative: %d", f.BlTxID)
	}
	inner, err := immudbInnerHash(f)
	if err != nil {
		return nil, err
	}
	innerHash := sha256.Sum256(inner)
	h := sha256.Sum256(concatBytes(longToBEBytes(f.TxID), f.PrevALH, innerHash[:]))
	return h[:], nil
}

// VerifyImmudbALHBinding verifies that the signed tx_hash (ALH) recorded in
// immudb (anchor_refs.immudb) cryptographically commits to tx_eH, per
// immudb's ALH construction (see ComputeImmudbALH). Returns false on any
// missing field, decode error, or mismatch.
func VerifyImmudbALHBinding(immudb map[string]interface{}, txHashBytes []byte) bool {
	txID, ok1 := getInt64Loose(immudb, "tx_id")
	ts, ok2 := getInt64Loose(immudb, "tx_ts")
	version, ok3 := getInt64Loose(immudb, "tx_version")
	blTxID, ok4 := getInt64Loose(immudb, "tx_bl_tx_id")
	nentries, ok5 := getInt64Loose(immudb, "tx_nentries")
	blRootB64, ok6 := getString(immudb, "tx_bl_root")
	prevALHB64, ok7 := getString(immudb, "tx_prev_alh")
	eHB64, ok8 := getString(immudb, "tx_eH")
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 || !ok8 {
		return false
	}
	prevALH, err1 := b64Decode(prevALHB64)
	blRoot, err2 := b64Decode(blRootB64)
	eH, err3 := b64Decode(eHB64)
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	alh, err := ComputeImmudbALH(ImmudbALHFields{
		TxID: txID, PrevALH: prevALH, TS: ts, Version: version,
		Nentries: nentries, EH: eH, BlTxID: blTxID, BlRoot: blRoot,
	})
	if err != nil {
		return false
	}
	return bytes.Equal(alh, txHashBytes)
}

// expectedImmudbEntryHash recomputes the expected immudb HTree entry_hash for
// this bundle's root_id and signed_root -- immudb's real HTree leaf over the
// (key, value) pair the notary commits to the HTree as (key = the
// 0x00-prefixed store key "\x00"+root_id, value = the canonical
// signable-fields encoding of the signed root), mirroring
// notary/anchor/immudb.clj's append-root!:
//
//	sha256(0x00 || sha256(uint16(mdLen) || md || uint16(kLen) ||
//	                       (0x00 || root_id) || sha256(0x00 || value)))
//
// with md empty and mdLen=0 (immudb's plain KV Set carries no metadata), and
// kLen = len(root_id)+1 (the 0x00-prefixed key's length). Byte-verified
// against codenotary/immudb 1.11.0 (i-dvp6); the earlier
// sha256(sha256(root_id) || sha256(value)) formula matched no real immudb.
func expectedImmudbEntryHash(rootID string, signedRoot map[string]interface{}) ([]byte, error) {
	signable := selectKeys(signedRoot, SignableRootFields)
	valueBytes, err := CanonicalJSONBytes(signable)
	if err != nil {
		return nil, err
	}
	valueHash := sha256.Sum256(concatBytes([]byte{0x00}, valueBytes))

	key := concatBytes([]byte{0x00}, []byte(rootID))
	mdLenBytes, err := shortToBEBytes(0)
	if err != nil {
		return nil, err
	}
	kLenBytes, err := shortToBEBytes(int64(len(key)))
	if err != nil {
		return nil, err
	}
	inner := sha256.Sum256(concatBytes(mdLenBytes, kLenBytes, key, valueHash[:]))
	h := sha256.Sum256(concatBytes([]byte{0x00}, inner[:]))
	return h[:], nil
}

// VerifyImmudbEntryHash verifies that the immudb anchor's entry_hash equals
// the expected recomputation from THIS bundle's root_id and signed_root (see
// expectedImmudbEntryHash) -- i.e. that this bundle's root_id/signed_root is
// the artifact the anchor's entry_hash actually commits to, closing the gap
// where a genuine, unrelated, validly-signed immudb anchor could be paired
// with a mismatched bundle root. Unlike the retired root_binding_hash side
// channel (an unsigned field covered by no signature), entry_hash is the
// value actually carried through immudb's real proof chain (inclusion proof
// -> tx_eH -> signed tx_hash), so this recomputation ties that chain directly
// to the bundle's own trusted content. Returns false on any decode/encode
// error or mismatch.
func VerifyImmudbEntryHash(entryHashB64, rootID string, signedRoot map[string]interface{}) bool {
	entryHash, err1 := b64Decode(entryHashB64)
	if err1 != nil {
		return false
	}
	expected, err2 := expectedImmudbEntryHash(rootID, signedRoot)
	if err2 != nil {
		return false
	}
	return bytes.Equal(expected, entryHash)
}

// VerifyImmudbState verifies the immudb server's ImmutableState signature
// using an out-of-band public key. For ECDSA, VerifySignature hashes the
// payload internally; for Ed25519, the payload is signed directly. Returns
// false on any decode or verification failure.
func VerifyImmudbState(stateDB string, txID int64, txHashB64, sigB64 string, immudbPubKey interface{}) bool {
	txHashBytes, err1 := b64Decode(txHashB64)
	sigBytes, err2 := b64Decode(sigB64)
	if err1 != nil || err2 != nil {
		return false
	}
	payload, err := buildImmudbStatePayload(stateDB, txID, txHashBytes)
	if err != nil {
		return false
	}
	return VerifySignature(immudbPubKey, payload, sigBytes)
}

// ImmudbResult is the outcome of [VerifyImmudbAnchor]. Status alone is
// tri-state (verified/failed/skipped) -- there is no separate "OK but
// skipped" flag, matching the Clojure reference's {:ok? true|false|:skipped}
// shape (see also [S3Result], which follows the same shape).
type ImmudbResult struct {
	Status AnchorStatus
	Detail string
}

// triState represents Clojure's true/false/:skipped result shape for one
// immudb proof component.
type triState int

const (
	triFalse triState = iota
	triTrue
	triSkipped
)

// VerifyImmudbAnchor validates the immudb anchor in anchorRefs: the HTree
// inclusion proof (entry_hash -> tx_eH), the server's ImmutableState
// signature over (db, tx_id, tx_hash), that tx_hash itself cryptographically
// commits to tx_eH (VerifyImmudbALHBinding), and that entry_hash itself
// equals the recomputed expected value from THIS bundle's root_id and
// signed_root (VerifyImmudbEntryHash), so a genuine but unrelated immudb
// anchor can't be paired with a mismatched bundle root. This supersedes the
// retired root_binding_hash side channel, which only bound entry_hash to
// root_hash_b64 via an unsigned field rather than recomputing entry_hash
// itself from the bundle's own trusted content.
//
// rootID is this bundle's own root_id (a single-record bundle's top-level
// root_id field, or a set bundle's signed_roots/anchor_refs_by_root map key)
// and signedRoot is this bundle's signed_root map for that root_id -- the
// trusted inputs the notary's entry_hash actually commits to. Pass
// immudbPubKey == nil to skip offline validation. When required is true, an
// absent anchor block -- or one present without a supplied key -- is a FAIL
// rather than SKIPPED, letting an auditor who knows an immudb anchor must
// exist detect either a stripped anchor or an unkeyed (and therefore
// entirely unverified) one.
func VerifyImmudbAnchor(anchorRefs map[string]interface{}, immudbPubKey interface{}, required bool, rootID string, signedRoot map[string]interface{}) ImmudbResult {
	immudb, ok := getMap(anchorRefs, "immudb")
	if !ok {
		if required {
			return ImmudbResult{AnchorFailed, "required immudb anchor is absent from bundle (--require-anchor immudb)"}
		}
		return ImmudbResult{AnchorSkipped, "no immudb anchor in bundle"}
	}
	if immudbPubKey == nil {
		if required {
			return ImmudbResult{AnchorFailed, "required immudb anchor present but no immudb public key provided (--require-anchor immudb); cannot validate"}
		}
		return ImmudbResult{AnchorSkipped, "no immudb public key provided; validation skipped"}
	}

	db, hasDB := getString(immudb, "state_db")
	if !hasDB {
		db, hasDB = getString(immudb, "database")
	}
	entryHashB64, hasEntryHash := getString(immudb, "entry_hash")
	eHB64, hasEH := getString(immudb, "tx_eH")
	nentries, hasNentries := getInt64Loose(immudb, "tx_nentries")
	txID, hasTxID := getInt64Loose(immudb, "tx_id")
	txHashB64, hasTxHash := getString(immudb, "tx_hash")
	stateSigB64, hasStateSig := getString(immudb, "state_signature")

	// Part 1: inclusion proof (entry_hash -> tx_eH).
	inclusionStatus := triSkipped
	if hasEntryHash && hasEH && hasNentries {
		entryHash, err1 := b64Decode(entryHashB64)
		eH, err2 := b64Decode(eHB64)
		proofRaw, _ := getSlice(immudb, "inclusion_proof")
		proof := make([]string, 0, len(proofRaw))
		for _, p := range proofRaw {
			if s, ok := p.(string); ok {
				proof = append(proof, s)
			}
		}
		switch {
		case err1 != nil || err2 != nil:
			inclusionStatus = triFalse
		case VerifyImmudbInclusion(entryHash, proof, nentries, eH):
			inclusionStatus = triTrue
		default:
			inclusionStatus = triFalse
		}
	}

	// Part 2: state signature over (db, tx_id, tx_hash).
	stateStatus := triSkipped
	if hasDB && hasTxID && hasTxHash && hasStateSig {
		if VerifyImmudbState(db, txID, txHashB64, stateSigB64, immudbPubKey) {
			stateStatus = triTrue
		} else {
			stateStatus = triFalse
		}
	}

	// Part 3: ALH binding -- the signed tx_hash must itself commit to
	// tx_eH, otherwise a fabricated (entry_hash, proof, tx_eH) triple can
	// be paired with a genuine but unrelated signed state and parts 1-2
	// alone would both pass.
	bindingStatus := triSkipped
	if hasEH && hasTxHash {
		_, hasTS := getInt64Loose(immudb, "tx_ts")
		_, hasVersion := getInt64Loose(immudb, "tx_version")
		_, hasBlTxID := getInt64Loose(immudb, "tx_bl_tx_id")
		_, hasBlRoot := getString(immudb, "tx_bl_root")
		_, hasPrevALH := getString(immudb, "tx_prev_alh")
		if hasTS && hasVersion && hasBlTxID && hasBlRoot && hasPrevALH && hasNentries {
			txHashBytes, err := b64Decode(txHashB64)
			if err == nil && VerifyImmudbALHBinding(immudb, txHashBytes) {
				bindingStatus = triTrue
			} else {
				bindingStatus = triFalse
			}
		} else {
			// Fields present (tx_eH/tx_hash) but the header fields needed
			// to recompute the ALH are absent -- fail closed, not skipped:
			// an anchor that predates ALH binding proves "a signed state
			// exists," not "this record is in that state."
			bindingStatus = triFalse
		}
	}

	// Part 4: entry-hash binding -- entry_hash must itself equal the
	// recomputed expected value from THIS bundle's root_id/signed_root,
	// otherwise a genuine but unrelated immudb anchor can be paired with a
	// mismatched bundle root and parts 1-3 above would all still pass. Fails
	// closed (not skipped) when entry_hash is present (a real anchor) but
	// root_id/signed_root are unavailable -- an absent trusted input must
	// not silently downgrade to skipped.
	entryHashStatus := triSkipped
	if hasEntryHash {
		switch {
		case rootID == "":
			entryHashStatus = triFalse
		case signedRoot == nil:
			entryHashStatus = triFalse
		case VerifyImmudbEntryHash(entryHashB64, rootID, signedRoot):
			entryHashStatus = triTrue
		default:
			entryHashStatus = triFalse
		}
	}

	absent := inclusionStatus == triSkipped && stateStatus == triSkipped && bindingStatus == triSkipped && entryHashStatus == triSkipped
	anyFalse := inclusionStatus == triFalse || stateStatus == triFalse || bindingStatus == triFalse || entryHashStatus == triFalse
	anySkipped := inclusionStatus == triSkipped || stateStatus == triSkipped || bindingStatus == triSkipped || entryHashStatus == triSkipped

	switch {
	case absent:
		return ImmudbResult{AnchorFailed, "immudb anchor proof material absent (bundle predates offline-proof support)"}
	case anyFalse:
		detail := "immudb proof failed:"
		if inclusionStatus == triFalse {
			detail += " inclusion_proof_invalid"
		}
		if stateStatus == triFalse {
			detail += " state_signature_invalid"
		}
		if bindingStatus == triFalse {
			detail += " alh_binding_invalid (tx_hash does not commit to tx_eH)"
		}
		if entryHashStatus == triFalse {
			detail += " entry_hash_invalid (anchor does not commit to bundle root_id/signed_root)"
		}
		return ImmudbResult{AnchorFailed, detail}
	case anySkipped:
		// A partial proof -- e.g. entry_hash/tx_eH stripped so
		// inclusion/binding are skipped while a genuine state_signature
		// still verifies -- must not read as a full pass: state-ok? alone
		// only proves *some* signed state exists, not that this record's
		// entry_hash is included in it.
		detail := "immudb proof incomplete (partial/stripped proof material):"
		if inclusionStatus == triSkipped {
			detail += " inclusion_proof_skipped"
		}
		if stateStatus == triSkipped {
			detail += " state_signature_skipped"
		}
		if bindingStatus == triSkipped {
			detail += " alh_binding_skipped"
		}
		if entryHashStatus == triSkipped {
			detail += " entry_hash_skipped"
		}
		return ImmudbResult{AnchorFailed, detail}
	default:
		return ImmudbResult{AnchorVerified, "immudb inclusion proof, state signature, ALH binding, and entry-hash binding verified"}
	}
}
