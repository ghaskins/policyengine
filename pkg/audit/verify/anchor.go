//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

// AnchorStatus is the outcome of an optional anchor's offline verification.
type AnchorStatus string

// Possible outcomes of verifying an anchor.
const (
	AnchorVerified AnchorStatus = "verified"
	AnchorFailed   AnchorStatus = "failed"
	AnchorSkipped  AnchorStatus = "skipped"
)
