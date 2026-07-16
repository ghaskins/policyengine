//
//  Copyright © Manetu Inc. All rights reserved.
//

package verify

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
)

var durationRe = regexp.MustCompile(
	`^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$`)

// ParseDuration parses an ISO 8601 duration string (e.g. "P6M", "P1Y30D",
// "PT1H") into milliseconds. Months are approximated as 30.4375 days
// (365.25/12); years as 365 days. Returns an error for an invalid or empty
// string.
//
// Approximation impact: P1Y (365 days) differs from P12M (12 x 30.4375 =
// 365.25 days) by ~6 hours; a mixed P1Y1M string accumulates similar
// errors. Near a retention-floor boundary this can flip an
// authorized-absent check by up to ~1 day -- acceptable because ILM
// deletion windows are configured in whole days and are typically weeks or
// months wide.
func ParseDuration(s string) (int64, error) {
	m := durationRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("verify: invalid ISO 8601 duration: %q", s)
	}
	allEmpty := true
	for _, g := range m[1:] {
		if g != "" {
			allEmpty = false
			break
		}
	}
	if allEmpty {
		return 0, fmt.Errorf("verify: invalid or empty ISO 8601 duration: %q", s)
	}
	const (
		msS = int64(1000)
		msM = 60 * msS
		msH = 60 * msM
		msD = 24 * msH
		msW = 7 * msD
	)
	msMo := int64(30.4375 * float64(msD))
	msY := int64(365 * msD)
	// toMs converts one component's digit string to milliseconds, checking
	// both the ParseInt and the n*unit multiplication for overflow. A
	// component that fits int64 on its own (e.g. a huge year count) can
	// still overflow once multiplied by its unit -- Go has no overflow
	// trap, so an unchecked multiply would wrap silently and understate
	// the parsed duration, exactly the failure mode this function's
	// doc comment already promises to surface rather than hide.
	toMs := func(g string, unit int64) (int64, error) {
		if g == "" {
			return 0, nil
		}
		n, err := strconv.ParseInt(g, 10, 64)
		if err != nil {
			// durationRe only admits digit runs, so this is exclusively a
			// component too large for int64 itself.
			return 0, fmt.Errorf("verify: invalid ISO 8601 duration %q: component %q out of range: %w", s, g, err)
		}
		if n != 0 && n > math.MaxInt64/unit {
			return 0, fmt.Errorf("verify: invalid ISO 8601 duration %q: component %q overflows int64 milliseconds", s, g)
		}
		return n * unit, nil
	}
	components := []struct {
		g    string
		unit int64
	}{
		{m[1], msY}, {m[2], msMo}, {m[3], msW}, {m[4], msD},
		{m[5], msH}, {m[6], msM}, {m[7], msS},
	}
	var total int64
	for _, c := range components {
		v, err := toMs(c.g, c.unit)
		if err != nil {
			return 0, err
		}
		// Every component is non-negative (durationRe only admits \d+, and
		// every unit constant above is positive), so int64::MAX is the
		// only overflow direction the running sum can hit.
		if total > math.MaxInt64-v {
			return 0, fmt.Errorf("verify: invalid ISO 8601 duration %q: total duration overflows int64 milliseconds", s)
		}
		total += v
	}
	return total, nil
}

// RetentionPolicy mirrors the signed_root.retention_policy bundle field.
type RetentionPolicy struct {
	Mode string
	P    string
}

// AuthorizedFloor returns the lowest record timestamp (epoch-ms) that must
// be present in the audit log.
//
//   - "retain-all" -- genesis mode; every record must be present; returns 0.
//   - "relative"   -- floor = trustedNowMs - ParseDuration(P); records with
//     timestamp < floor are authorized-absent (ILM deletion is expected;
//     absence is not a tamper violation).
//
// Any other mode -- including an empty string, which callers must not
// substitute for a genuinely absent retention_policy -- is an error.
func AuthorizedFloor(rp RetentionPolicy, trustedNowMs int64) (int64, error) {
	switch rp.Mode {
	case "retain-all":
		return 0, nil
	case "relative":
		d, err := ParseDuration(rp.P)
		if err != nil {
			return 0, err
		}
		return trustedNowMs - d, nil
	default:
		return 0, fmt.Errorf("verify: unknown retention-policy mode %q", rp.Mode)
	}
}

// retentionFloorOK is Step 6's tri-state result: true if timestampMs clears
// the authorized floor (record must be present), false if timestampMs is
// authorized-absent (ILM deletion expected, not a tamper signal), or nil if
// the retention policy could not be parsed -- fail-closed, callers must
// treat nil as a failure, never as a silent pass.
//
// A wholly absent retentionPolicy defaults to retain-all (every record must
// be present); a present-but-mode-less retentionPolicy is a parse error, not
// a silent retain-all default -- mirroring notary/verify.clj's
// retention-floor-ok?/authorized-floor split exactly.
func retentionFloorOK(timestampMs int64, retentionPolicy map[string]interface{}, trustedNowMs int64) *bool {
	rp := RetentionPolicy{Mode: "retain-all"}
	if retentionPolicy != nil {
		mode, _ := getString(retentionPolicy, "mode")
		p, _ := getString(retentionPolicy, "P")
		rp = RetentionPolicy{Mode: mode, P: p}
	}
	floor, err := AuthorizedFloor(rp, trustedNowMs)
	if err != nil {
		return nil
	}
	ok := timestampMs >= floor
	return &ok
}
