// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pipeline

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// newCrossOriginValidator returns the probe.Config.URLValidator implementing
// the SEC-BE-001 cross-origin gate: rawURL is rejected unless it shares
// targetOrigin's scheme+host+port (per crawl.SameOrigin); otherwise it
// delegates to base, the SSRF/allow-private validator already installed on
// cfg. Extracted from ClassifyProbeGenerate (code-quality review, "moderate
// complexity" finding) so the gate is a small, independently testable
// function taking its inputs as plain parameters — no interface or struct.
//
// targetOrigin == "" is deliberately NOT special-cased: crawl.SameOrigin
// already returns false whenever either side's origin can't be resolved
// (its doc comment: a "" left-hand origin never compares equal), so an
// unresolvable target origin fails closed — every candidate rejected —
// without an extra `targetOrigin == ""` guard. Verified by mutation: deleting
// such a guard here leaves the full suite green, the same situation commit
// 851a41f resolved for the concat guard's dead terms; removed here for the
// same reason (code-quality review, redundant-term finding).
//
// Per-URL skip warnings are deduped by rawURL's origin (not path), so a
// capture with many cross-origin candidates on one attacker host emits a
// single warning line instead of one per URL.
func newCrossOriginValidator(base func(string) error, targetOrigin string, warnings io.Writer) func(string) error {
	warnedOrigins := make(map[string]bool)
	return func(rawURL string) error {
		if crawl.SameOrigin(rawURL, targetOrigin) {
			return base(rawURL)
		}
		origin := bestEffortOrigin(rawURL)
		if !warnedOrigins[origin] {
			warnedOrigins[origin] = true
			writeStatus(warnings,
				"probe: skipping cross-origin URL %s (use AllowCrossOriginProbe to allow)\n", rawURL)
		}
		return fmt.Errorf("probe: cross-origin URL rejected: %s", rawURL)
	}
}

// bestEffortOrigin returns a lowercased "scheme://host" for rawURL, or "" if
// it can't be parsed or has no host. This exists only to dedupe warnings
// above (reducing operator noise); unlike crawl's origin comparison it does
// not canonicalize default ports, so it must never be used for the actual
// same-origin security decision (that stays exclusively in crawl.SameOrigin).
func bestEffortOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// warnDerivedProbeOrigin emits a one-time, always-on warning — mirroring
// crawl.warnDerivedOrigin (LAB-4998) — when --target-url was not supplied, so
// the probe-stage cross-origin gate (SEC-BE-001) is comparing candidates
// against an origin DERIVED from the capture rather than one the operator
// chose. Without this, an operator whose real API endpoints are silently
// skipped (e.g. a mixed-origin HAR/Burp import whose first entry is a
// third-party CDN) has no signal explaining why, or that --target-url is the
// fix. Called once per ClassifyProbeGenerate invocation, not per candidate.
func warnDerivedProbeOrigin(w io.Writer, targetOrigin string) {
	if targetOrigin == "" {
		writeStatus(w, "WARNING: --target-url not set and no usable origin could be derived from the capture; "+
			"the probe-stage cross-origin gate (SEC-BE-001) will reject every probe candidate. "+
			"Pass --target-url to allow probing.\n")
		return
	}
	writeStatus(w, "WARNING: --target-url not set; probe-stage cross-origin gate (SEC-BE-001) derived origin %s "+
		"from the capture — endpoints outside this origin will be skipped. Pass --target-url to pin it.\n", targetOrigin)
}
