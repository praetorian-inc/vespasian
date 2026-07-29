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
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// newCrossOriginValidator returns the probe.Config.URLValidator implementing
// the SEC-BE-001 cross-origin gate: rawURL is rejected unless it shares
// targetOrigin's scheme+host+port (per crawl.SameOrigin); otherwise it
// delegates to base, the SSRF/allow-private validator already installed on
// cfg. Extracted from ClassifyProbeGenerate (code-quality review, "moderate
// complexity" finding) so the gate is a small, independently testable
// function taking its inputs as plain parameters — no interface or struct.
//
// cfgValidator is cfg.URLValidator as it stands when this is called: nil in
// the default (AllowPrivate=false) path, or the AllowPrivate no-op override.
// A nil cfgValidator falls back to probe.ValidateProbeURL here (moved in from
// ClassifyProbeGenerate, TEST-003 review finding) specifically so that
// fallback selection is exercised by a direct unit test: a black-box test
// driving this through a real network probe cannot distinguish "the fallback
// was skipped" from "the fallback ran but was overridden" for a loopback
// target, because probe.Config's Dialer independently re-checks the same
// private-IP predicate at connect time (defense-in-depth) regardless of what
// URLValidator decided — so a same-origin loopback candidate is rejected
// either way and the two mutations are behaviorally invisible over the wire.
// Keeping the fallback here, in the same function this package already unit
// tests directly, closes that gap without adding an interface or DI seam.
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
// The parse-time userinfo/scheme gate (SEC-BE-001: crawl.SameOrigin compares
// via u.Hostname(), which excludes userinfo entirely, so
// "https://user:pass@<targethost>/api/x" is judged same-origin, and neither
// base (SSRF: scheme + resolved IPs only) nor anything upstream of this point
// inspects u.User) is applied by newFullURLValidator, NOT here — it wraps
// whatever this function returns from the pipeline.go call site, unconditional
// on AllowCrossOriginProbe, so it is never skipped together with the
// cross-origin check this function performs. See newFullURLValidator's doc
// comment for why it lives at that call site instead of inside this
// function's same-origin arm.
//
// Per-URL skip warnings are deduped by rawURL's origin (not path), so a
// capture with many cross-origin candidates on one attacker host emits a
// single warning line instead of one per URL.
//
// warnedOrigins is an unsynchronized plain map, safe only because
// probe.RunStrategies (the sole caller of the validator this returns) invokes
// probe strategies sequentially today. If that ever becomes concurrent, every
// call into the closure returned here would need external synchronization
// (e.g. a mutex around the map) to avoid a data race; a mutex is deliberately
// NOT added now (KISS — guarding a race that cannot currently occur is
// complexity for no present benefit), so this comment is the tripwire for
// whoever parallelizes RunStrategies next (SEC-BE-003).
func newCrossOriginValidator(cfgValidator func(string) error, targetOrigin string, warnings io.Writer) func(string) error {
	base := cfgValidator
	if base == nil {
		base = probe.ValidateProbeURL
	}
	warnedOrigins := make(map[string]bool)
	return func(rawURL string) error {
		if crawl.SameOrigin(rawURL, targetOrigin) {
			return base(rawURL)
		}
		origin := bestEffortOrigin(rawURL)
		if !warnedOrigins[origin] {
			warnedOrigins[origin] = true
			writeStatus(warnings,
				"probe: skipping cross-origin URL %s (use AllowCrossOriginProbe to allow)\n",
				crawl.SanitizeForLog(rawURL))
		}
		return fmt.Errorf("probe: cross-origin URL rejected: %s", rawURL)
	}
}

// newFullURLValidator wraps base with crawl.ValidateFullURL (SEC-BE-001):
// rawURL is rejected unless it passes that parse-time userinfo/scheme gate,
// the same one JS-replay's addPath and jsstatic's synthesis choke point
// (specSafeURL) already apply to this sink. Only ValidateFullURL's boolean is
// used; see newCrossOriginValidator's (former) identical note -- its
// normalized/cleaned URL string is discarded because probe.Config.URLValidator's
// signature (func(string) error) has no channel to feed a rewritten URL back
// to the caller that actually issues the request, so rawURL is what gets
// probed either way.
//
// Called unconditionally at the pipeline.go call site -- after and outside the
// `if !opts.AllowCrossOriginProbe` branch -- rather than composed into
// newCrossOriginValidator's same-origin arm (where it lived before), because
// AllowCrossOriginProbe disabling the cross-origin gate must not also disable
// this independent parse-time gate (SEC-BE-001 review finding: they were
// previously coupled, so AllowCrossOriginProbe:true silently dropped both).
// Also not composed into probe.ValidateProbeURL itself: that function is the
// exported default for pkg/probe, which pkg/sdk consumes directly, and this is
// a low-severity finding that does not justify changing that shared default's
// behavior for every caller.
//
// A nil base falls back to probe.ValidateProbeURL, mirroring
// newCrossOriginValidator's identical nil-fallback: base is nil whenever
// AllowCrossOriginProbe is true and AllowPrivate is false, since
// probe.DefaultConfig() leaves Config.URLValidator nil in that combination
// and no other branch in ClassifyProbeGenerate sets it.
func newFullURLValidator(base func(string) error) func(string) error {
	if base == nil {
		base = probe.ValidateProbeURL
	}
	return func(rawURL string) error {
		if _, ok := crawl.ValidateFullURL(rawURL); !ok {
			return fmt.Errorf("probe: URL rejected by parse-time validation: %s", rawURL)
		}
		return base(rawURL)
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
		"from the capture — endpoints outside this origin will be skipped. Pass --target-url to pin it.\n",
		crawl.SanitizeForLog(targetOrigin))
}
