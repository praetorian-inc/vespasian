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

package pipeline_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// countingAPIServer returns an httptest server that increments hits on every
// request and answers a minimal JSON body, plus the counter itself.
func countingAPIServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// apiRequest builds a minimal REST-classifiable ObservedRequest for rawURL
// (JSON content-type response on an /api/ path, matching classify Rule 2/3).
func apiRequest(rawURL string) crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method:  "GET",
		URL:     rawURL,
		Headers: map[string]string{"Content-Type": "application/json"},
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/json",
			Headers:     map[string]string{"Content-Type": "application/json"},
			Body:        []byte(`{"id":1}`),
		},
	}
}

// TestClassifyProbeGenerate_SameOriginCandidateIsProbed pins the positive half
// of the SEC-BE-001 origin gate: a candidate whose URL shares TargetURL's
// origin must still be probed (the gate must not fail closed for legitimate
// same-origin targets).
func TestClassifyProbeGenerate_SameOriginCandidateIsProbed(t *testing.T) {
	target, hits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{apiRequest(target.URL + "/api/v1/users")}

	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		TargetURL:    target.URL,
	})
	require.NoError(t, err)

	assert.Positive(t, atomic.LoadInt32(hits), "same-origin candidate must be probed")
}

// TestClassifyProbeGenerate_SameOriginLoopbackRejectedWithoutAllowPrivate is
// the TEST-003 regression test: it is the only test in this file that
// exercises the gate in its default, shipped configuration (AllowPrivate:
// false, so baseValidator falls back to probe.ValidateProbeURL at
// pipeline.go rather than being replaced by the AllowPrivate no-op). Every
// other test in this file sets AllowPrivate: true, which installs an
// origin-blind no-op validator BEFORE the gate wraps it — so the gate's
// same-origin arm (`return base(rawURL)`) and the production-default
// baseValidator fallback are both completely unpinned by those tests: either
// could be reduced to `return nil` and the suite would stay green, silently
// deleting SSRF/private-IP enforcement for every same-origin probe target.
//
// The httptest server here is same-origin (TargetURL == its own URL) but
// resolves to a loopback/private IP, so probe.ValidateProbeURL (ssrf.ValidateURL
// under the hood) must reject it even though crawl.SameOrigin says yes —
// proving the same-origin arm truly delegates to the SSRF validator rather
// than short-circuiting to an unconditional allow. Pairs with
// TestClassifyProbeGenerate_SameOriginCandidateIsProbed (AllowPrivate: true)
// as the positive control.
func TestClassifyProbeGenerate_SameOriginLoopbackRejectedWithoutAllowPrivate(t *testing.T) {
	target, hits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{apiRequest(target.URL + "/api/v1/users")}

	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: false,
		Deduplicate:  true,
		TargetURL:    target.URL,
	})
	require.NoError(t, err)

	assert.Zero(t, atomic.LoadInt32(hits),
		"a same-origin loopback candidate must still be rejected by the SSRF validator "+
			"when AllowPrivate is false (the shipped default)")
}

// TestClassifyProbeGenerate_UserinfoRejectedEvenWithCrossOriginProbeAllowed pins
// the UNCONDITIONAL half of SEC-BE-001: crawl.ValidateFullURL's parse-time
// userinfo/scheme gate must survive AllowCrossOriginProbe: true. The two gates are
// independent concerns — the origin gate decides WHERE a probe may go, the
// parse-time gate decides whether the URL is safe to issue at all — and they were
// previously coupled, with ValidateFullURL living inside newCrossOriginValidator's
// same-origin arm so the opt-out silently disabled both.
//
// Verified by mutation: moving `cfg.URLValidator = newFullURLValidator(...)` back
// inside the `if !opts.AllowCrossOriginProbe` branch in pipeline.go leaves every
// other test in the repository green, so without this test the exact defect
// SEC-BE-001 was raised about could be reintroduced undetected. The sibling test
// below covers the same rejection in the default (opt-out off) configuration.
//
// user:pass is synthetic test data, not a real secret; the fixture asserts REJECTION.
func TestClassifyProbeGenerate_UserinfoRejectedEvenWithCrossOriginProbeAllowed(t *testing.T) {
	target, hits := countingAPIServer(t)

	userinfoURL := strings.Replace(target.URL, "://", "://user:pass@", 1) + "/api/v1/x"
	requests := []crawl.ObservedRequest{apiRequest(userinfoURL)}

	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:               pipeline.APITypeREST,
		Confidence:            0.5,
		Probe:                 true,
		AllowPrivate:          true,
		Deduplicate:           true,
		TargetURL:             target.URL,
		AllowCrossOriginProbe: true, // origin gate OFF; parse-time gate must remain ON
	})
	require.NoError(t, err)

	assert.Zero(t, atomic.LoadInt32(hits),
		"AllowCrossOriginProbe disables only the cross-origin gate; the parse-time userinfo "+
			"gate (crawl.ValidateFullURL) must still reject this candidate")
}

// TestClassifyProbeGenerate_SameOriginUserinfoCredentialInjectionRejected is
// the SEC-BE-001 regression test, and the PRIMARY pin for same-origin
// userinfo rejection: crawl.SameOrigin compares via u.Hostname(), which
// excludes userinfo entirely, so a same-origin candidate spelled
// "http://user:pass@<targethost>/api/x" is judged same-origin by the gate.
// AllowPrivate is true here specifically to isolate this assertion from the
// SSRF layer (ssrf.ValidateURL also never inspects userinfo) — proving
// crawl.ValidateFullURL is what rejects the embedded credentials, not
// something incidental to SSRF screening. Without this gate, net/http would
// derive an `Authorization: Basic <base64(user:pass)>` header from
// req.URL.User and send it to the target on the operator's behalf.
//
// Mutation-verified: deleting the ValidateFullURL rejection in
// newFullURLValidator (so it always falls through to base) turns hits
// positive and fails this test.
func TestClassifyProbeGenerate_SameOriginUserinfoCredentialInjectionRejected(t *testing.T) {
	target, hits := countingAPIServer(t)

	// user:pass is synthetic test data, not a real secret; this fixture asserts
	// REJECTION by the credential gate (see doc comment above).
	userinfoURL := strings.Replace(target.URL, "://", "://user:pass@", 1) + "/api/v1/x"

	requests := []crawl.ObservedRequest{apiRequest(userinfoURL)}

	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		TargetURL:    target.URL,
	})
	require.NoError(t, err)

	// NOTE for alert triage: titus reports "HTTP Basic Authentication" against
	// this assertion's MESSAGE, not against any credential. The finding is the
	// phrase "Authorization: Basic" in the prose below -- there is no secret on
	// this line. Left as-is: the message names the exact header the gate exists
	// to prevent, which is the clearest way to state the failure.
	assert.Zero(t, atomic.LoadInt32(hits),
		"a same-origin candidate carrying userinfo credentials must be rejected by crawl.ValidateFullURL "+
			"rather than probed with an attacker-derived Authorization: Basic header")
}

// TestClassifyProbeGenerate_CrossOriginCandidateIsNotProbed pins the negative
// half of the SEC-BE-001 origin gate AND doubles as the AllowPrivate-ordering
// regression test: AllowPrivate=true is required here for the loopback
// attacker server to even be dial-able, so if the origin gate were applied
// BEFORE the opts.AllowPrivate branch in ClassifyProbeGenerate (which replaces
// cfg.URLValidator with an origin-blind no-op), the attacker server would
// receive the probe request and this test would fail. It must therefore fail
// if the gate is moved before that branch.
func TestClassifyProbeGenerate_CrossOriginCandidateIsNotProbed(t *testing.T) {
	target, targetHits := countingAPIServer(t)
	attacker, attackerHits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{
		apiRequest(target.URL + "/api/v1/users"),
		apiRequest(attacker.URL + "/api/v1/collect"),
	}

	// Status is deliberately left nil (verbose off): the cross-origin skip
	// warning must NOT depend on --verbose (see TestClassifyProbeGenerate_
	// CrossOriginWarningNotGatedByStatus for the dedicated regression test),
	// so it is asserted here on Warnings instead, mirroring
	// crawl.JSReplayConfig.Stderr / AugmentOptions.WarnError.
	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		TargetURL:    target.URL,
		Warnings:     &warnings,
	})
	require.NoError(t, err)

	assert.Positive(t, atomic.LoadInt32(targetHits), "same-origin candidate must still be probed")
	assert.Zero(t, atomic.LoadInt32(attackerHits), "cross-origin candidate must NOT be probed")
	assert.Contains(t, warnings.String(), "skipping cross-origin candidates for",
		"a warning must be emitted when a cross-origin probe target is skipped")
	assert.Contains(t, warnings.String(), "AllowCrossOriginProbe",
		"the warning must name the opt-out field, mirroring jsreplay's AllowCrossOrigin wording style")
}

// TestClassifyProbeGenerate_CrossOriginRejectWithNilWarnings is the TEST-004
// regression test: Options.Warnings documents "Pass nil to stay fully quiet
// (e.g. the SDK)", and pkg/sdk never sets it, yet no test exercised the
// per-URL cross-origin skip warning's nil-writer path (writeStatus at
// probe_origin_gate.go). This mirrors
// TestClassifyProbeGenerate_CrossOriginCandidateIsNotProbed but leaves
// Warnings nil — the SDK's exact configuration — and gives the cross-origin
// candidate a non-asset path (not .js) so it actually reaches the validator
// rather than being filtered out by classify's static-asset exclusion first.
func TestClassifyProbeGenerate_CrossOriginRejectWithNilWarnings(t *testing.T) {
	target, targetHits := countingAPIServer(t)
	attacker, attackerHits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{
		apiRequest(target.URL + "/api/v1/users"),
		apiRequest(attacker.URL + "/api/v1/collect"),
	}

	assert.NotPanics(t, func() {
		_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
			APIType:      pipeline.APITypeREST,
			Confidence:   0.5,
			Probe:        true,
			AllowPrivate: true,
			Deduplicate:  true,
			TargetURL:    target.URL,
			Warnings:     nil, // the SDK's exact configuration
		})
		require.NoError(t, err)
	}, "the cross-origin reject path must not panic when Warnings is nil")

	assert.Positive(t, atomic.LoadInt32(targetHits), "same-origin candidate must still be probed")
	assert.Zero(t, atomic.LoadInt32(attackerHits), "cross-origin candidate must NOT be probed even with Warnings nil")
}

// TestClassifyProbeGenerate_CrossOriginWarningNotGatedByStatus is the direct
// regression test for the review finding that cross-origin probe skips were
// silent by default: Status (the --verbose sink) is left nil here, exactly
// the default non-verbose CLI invocation, yet the skip warning must still
// reach Warnings. Prior to the fix, this warning only ever reached Status
// (nil in the default CLI invocation), so it was invisible without
// --verbose; this test pins the fix, not the pre-fix behavior.
func TestClassifyProbeGenerate_CrossOriginWarningNotGatedByStatus(t *testing.T) {
	target, _ := countingAPIServer(t)
	attacker, attackerHits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{
		apiRequest(target.URL + "/api/v1/users"),
		apiRequest(attacker.URL + "/api/v1/collect"),
	}

	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		TargetURL:    target.URL,
		Status:       nil, // verbose off
		Warnings:     &warnings,
	})
	require.NoError(t, err)

	assert.Zero(t, atomic.LoadInt32(attackerHits), "cross-origin candidate must NOT be probed")
	assert.Contains(t, warnings.String(), "skipping cross-origin candidates for",
		"the cross-origin skip warning must be emitted on Warnings even when Status (--verbose) is nil")
}

// TestClassifyProbeGenerate_CrossOriginWarningDedupedByOrigin proves that
// many cross-origin candidates on the SAME rejected origin produce exactly
// one skip-warning line, not one per URL — avoiding log spam from a bundle
// with many candidates on one attacker host.
func TestClassifyProbeGenerate_CrossOriginWarningDedupedByOrigin(t *testing.T) {
	target, _ := countingAPIServer(t)
	attacker, attackerHits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{
		apiRequest(target.URL + "/api/v1/users"),
		apiRequest(attacker.URL + "/api/v1/collect"),
		apiRequest(attacker.URL + "/api/v1/exfiltrate"),
		apiRequest(attacker.URL + "/api/v1/beacon"),
	}

	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		TargetURL:    target.URL,
		Warnings:     &warnings,
	})
	require.NoError(t, err)

	assert.Zero(t, atomic.LoadInt32(attackerHits), "no cross-origin candidate must be probed")
	assert.Equal(t, 1, strings.Count(warnings.String(), "skipping cross-origin candidates for"),
		"three candidates on the same rejected origin must produce exactly one skip warning, not three")
}

// TestClassifyProbeGenerate_CrossOriginWarningNotOverCollapsedAcrossHosts is
// the TEST-005 regression test: it pins the dedupe map in the "do not
// over-collapse" direction, which TestClassifyProbeGenerate_
// CrossOriginWarningDedupedByOrigin (a single attacker host) cannot exercise.
// Mutating bestEffortOrigin's body to `return ""` makes every rejected URL
// key identically, collapsing an operator's real multi-host mixed capture
// (see TestClassifyProbeGenerate_MixedOriginWithoutTargetURLSkipsRealAPI) into
// a single warning line naming only the first rejected URL — silently hiding
// every subsequent cross-origin host from the operator. Two DISTINCT
// cross-origin hosts here must therefore produce two warning lines, each
// naming its own host.
func TestClassifyProbeGenerate_CrossOriginWarningNotOverCollapsedAcrossHosts(t *testing.T) {
	target, _ := countingAPIServer(t)
	attacker1, attacker1Hits := countingAPIServer(t)
	attacker2, attacker2Hits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{
		apiRequest(target.URL + "/api/v1/users"),
		apiRequest(attacker1.URL + "/api/v1/collect"),
		apiRequest(attacker2.URL + "/api/v1/exfiltrate"),
	}

	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		TargetURL:    target.URL,
		Warnings:     &warnings,
	})
	require.NoError(t, err)

	assert.Zero(t, atomic.LoadInt32(attacker1Hits), "no cross-origin candidate must be probed")
	assert.Zero(t, atomic.LoadInt32(attacker2Hits), "no cross-origin candidate must be probed")
	assert.Equal(t, 2, strings.Count(warnings.String(), "skipping cross-origin candidates for"),
		"two DISTINCT cross-origin hosts must each produce their own skip warning, not collapse to one")
	assert.Contains(t, warnings.String(), attacker1.URL, "the first host must be named in a warning")
	assert.Contains(t, warnings.String(), attacker2.URL, "the second host must be named in a warning")
}

// TestClassifyProbeGenerate_CrossOriginWarningExcludesUserinfoCredentials is
// the direct regression test for the fix that prompted this warning's wording
// change: a cross-origin candidate can carry embedded HTTP Basic userinfo
// (e.g. a URL recovered from a Burp/HAR capture that still has the
// operator's own credentials embedded), and this always-on
// (not gated on --verbose) warning must never echo them in cleartext.
// bestEffortOrigin is userinfo-free by construction -- url.URL.Host excludes
// userinfo; u.User holds it separately (see newCrossOriginValidator's doc
// comment) -- so only the origin is printed, never the credential-bearing
// rawURL.
//
// user:pass is synthetic test data on a loopback httptest server (RFC 2606 /
// loopback-equivalent fixture), not a real secret; this fixture asserts
// NON-DISCLOSURE -- the credential must never appear in Warnings, in any
// form.
//
// Mutation-verified: reverting the production line in probe_origin_gate.go
// to print crawl.SanitizeForLog(rawURL) instead of crawl.SanitizeForLog(origin)
// makes this test fail, since the quoted rawURL then contains "user:pass".
func TestClassifyProbeGenerate_CrossOriginWarningExcludesUserinfoCredentials(t *testing.T) {
	target, _ := countingAPIServer(t)
	attacker, attackerHits := countingAPIServer(t)

	// user:pass is synthetic test data, not a real secret; see doc comment.
	attackerUserinfoURL := strings.Replace(attacker.URL, "://", "://user:pass@", 1) + "/api/v1/collect"
	requests := []crawl.ObservedRequest{
		apiRequest(target.URL + "/api/v1/users"),
		apiRequest(attackerUserinfoURL),
	}

	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		TargetURL:    target.URL,
		Warnings:     &warnings,
	})
	require.NoError(t, err)

	assert.Zero(t, atomic.LoadInt32(attackerHits), "cross-origin candidate must NOT be probed")
	assert.NotContains(t, warnings.String(), "user:pass",
		"the cross-origin skip warning must never echo embedded userinfo credentials in cleartext")
	assert.NotContains(t, warnings.String(), "user%3Apass",
		"the cross-origin skip warning must never echo a percent-encoded re-encoding of the credential either")
	assert.NotContains(t, warnings.String(), "user@",
		"the cross-origin skip warning must never echo the username-only portion of the credential either")
	// Pin the cross-origin warning LINE, not the whole buffer. Asserting on
	// warnings.String() coupled this test to every other writer on that sink
	// (warnDerivedProbeOrigin in particular), so an unrelated wording change
	// there broke it while a real leak on a DIFFERENT line could still pass.
	// Selecting our line first keeps the strictness where it belongs: any
	// content appended or re-encoded onto THIS line (e.g. a debug
	// "cand=<rawURL>" suffix) still fails, which the credential-specific
	// NotContains assertions above cannot catch on their own -- they remain
	// only because they name the exact leak shapes in the failure message.
	var gotLine string
	for _, line := range strings.Split(warnings.String(), "\n") {
		if strings.Contains(line, "skipping cross-origin candidates") {
			gotLine = line
			break
		}
	}
	require.NotEmpty(t, gotLine, "expected a cross-origin skip warning; got: %q", warnings.String())
	assert.Equal(t, "probe: skipping cross-origin candidates for \""+attacker.URL+"\" (use AllowCrossOriginProbe to allow)",
		gotLine,
		"the warning line must contain nothing but the credential-free, quoted origin")
}

// TestClassifyProbeGenerate_AllowCrossOriginProbeOptOut proves the internal
// opt-out field permits cross-origin probing when explicitly set.
func TestClassifyProbeGenerate_AllowCrossOriginProbeOptOut(t *testing.T) {
	target, _ := countingAPIServer(t)
	attacker, attackerHits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{
		apiRequest(target.URL + "/api/v1/users"),
		apiRequest(attacker.URL + "/api/v1/collect"),
	}

	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:               pipeline.APITypeREST,
		Confidence:            0.5,
		Probe:                 true,
		AllowPrivate:          true,
		Deduplicate:           true,
		TargetURL:             target.URL,
		AllowCrossOriginProbe: true,
	})
	require.NoError(t, err)

	assert.Positive(t, atomic.LoadInt32(attackerHits),
		"AllowCrossOriginProbe=true must permit probing the cross-origin candidate")
}

// TestClassifyProbeGenerate_UnresolvableOriginFailsClosed pins the gate's
// fail-closed branch (`targetOrigin == ""`): when neither an explicit
// TargetURL nor any request in the capture yields a usable origin,
// crawl.ResolveTargetOrigin returns "" and EVERY probe candidate must be
// rejected — not implicitly treated as same-origin.
//
// Constructing this at the ClassifyProbeGenerate level with a dialable
// candidate is impossible by design: ResolveTargetOrigin's third fallback
// scans every request for the first one with a resolvable origin, so any
// request carrying an absolute http(s) URL (the only kind an httptest server
// could ever receive a hit from) would itself make the resolved origin
// non-empty. A relative-path candidate (no scheme, no host) is therefore the
// only way to reach targetOrigin == "" while still having something
// classified and handed to a probe strategy: crawl.ResolveTargetOrigin("",
// requests) below is asserted "" as a precondition check, and RESTClassifier
// still classifies the relative URL (Rule 2, JSON content-type) so it reaches
// the gate. Because a relative URL can never be dialed by net/http regardless
// of the gate's outcome (confirmed separately: url.Parse gives it no host, so
// http.Client.Do fails before any TCP connection), a request-counter
// assertion cannot distinguish fail-closed from fail-open here; the status
// message the gate writes on its reject branch is the only observable signal
// tied to the branch under test, so it is asserted as the value-level
// evidence in its place (per SEC-BE-001 rejecting this exact candidate).
//
// The gate's warning now prints bestEffortOrigin(rawURL), not rawURL itself
// (see newCrossOriginValidator's doc comment: printing rawURL could echo
// embedded userinfo credentials to this always-on writer). Because the only
// candidate reachable here is relative ("/api/v1/users", no host, forced by
// the constraint above), its origin is "" -- and crawl.SanitizeForLog
// special-cases "" to return it unquoted, so this specific fixture cannot
// demonstrate the sanitizer's quoting behavior. That proof lives instead in
// TestClassifyProbeGenerate_MixedOriginWithoutTargetURLSkipsRealAPI, where
// the rejected candidate's origin is non-empty.
func TestClassifyProbeGenerate_UnresolvableOriginFailsClosed(t *testing.T) {
	requests := []crawl.ObservedRequest{apiRequest("/api/v1/users")}
	require.Equal(t, "", crawl.ResolveTargetOrigin("", requests),
		"precondition: this capture must resolve to an empty target origin")

	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		Warnings:     &warnings,
	})
	require.NoError(t, err)

	assert.Contains(t, warnings.String(), "skipping cross-origin candidates for",
		"an unresolvable target origin must fail closed and reject every probe candidate")
	assert.Contains(t, warnings.String(), "AllowCrossOriginProbe",
		"the warning must name the opt-out field even when the origin could not be resolved at all")
	assert.Contains(t, warnings.String(), "no usable origin could be derived",
		"the one-time derived-origin warning must also fire and explain that no origin could be resolved at all")
}

// TestClassifyProbeGenerate_CrossOriginGateRunsBeforeParseTimeGate is the
// TEST-003 regression test: it pins the newFullURLValidator /
// newCrossOriginValidator composition order directly and on purpose, rather
// than incidentally through TestClassifyProbeGenerate_UnresolvableOriginFailsClosed
// (whose relative-URL fixture exercises the same ordering only as a side
// effect of forcing crawl.ResolveTargetOrigin to return ""). The candidate
// here is BOTH cross-origin (a different host than TargetURL) AND carries
// userinfo (which newFullURLValidator's parse-time gate would ALSO reject,
// silently -- see its doc comment). With the composition pipeline.go
// documents (origin gate outermost), crawl.SameOrigin rejects it before
// ValidateFullURL ever runs, so the cross-origin warning fires. If the two
// wraps were swapped, the parse-time gate would reject it first -- silently,
// and without ever reaching the cross-origin check -- so the cross-origin
// warning would never appear, and its absence is what this test detects.
func TestClassifyProbeGenerate_CrossOriginGateRunsBeforeParseTimeGate(t *testing.T) {
	target, _ := countingAPIServer(t)
	attacker, attackerHits := countingAPIServer(t)

	attackerUserinfoURL := strings.Replace(attacker.URL, "://", "://user:pass@", 1) + "/api/v1/collect"
	requests := []crawl.ObservedRequest{
		apiRequest(target.URL + "/api/v1/users"),
		apiRequest(attackerUserinfoURL),
	}

	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		TargetURL:    target.URL,
		Warnings:     &warnings,
	})
	require.NoError(t, err)

	assert.Zero(t, atomic.LoadInt32(attackerHits), "cross-origin candidate must not be probed")
	assert.Contains(t, warnings.String(), "skipping cross-origin candidates for",
		"the origin gate must run first (outermost): a candidate that is both cross-origin and "+
			"userinfo-bearing must be rejected there, proving the composition order pipeline.go documents")
}

// thirdPartyAssetServer returns an httptest server used only to mint a
// second, distinct origin for mixed-origin capture tests (e.g. a CDN hosting
// a third-party asset) — it exists purely to occupy the "first request" slot
// in a mixed-origin capture (TEST-006).
//
// Its handler is never actually invoked by either call site: both wrap it
// with apiRequest(cdn.URL + "/analytics.js"), which synthesizes an
// ObservedRequest carrying its own application/json response record rather
// than issuing a live HTTP request. The CDN entry is excluded from
// firstHTMLOrigin/classification not because of anything this handler
// returns, but because (a) apiRequest's response carries an
// application/json Content-Type, so firstHTMLOrigin's HTML sniff never
// matches it, and (b) the ".js" extension on its URL is on
// pkg/classify/rest.go's static-asset exclusion list, so RESTClassifier
// never promotes it to an API candidate. hits counts requests that actually
// reach this handler — expected to stay zero in every caller — so a future
// change to either exclusion mechanism that turned the CDN entry into a live
// probe target would be caught here rather than passing silently.
func thirdPartyAssetServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("// analytics beacon\n"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestClassifyProbeGenerate_MixedOriginWithoutTargetURLSkipsRealAPI pins Gap
// 2's hazard exactly as it currently behaves: in a mixed-origin capture (as a
// HAR/Burp import might produce) with no HTML response anywhere and no
// --target-url, crawl.ResolveTargetOrigin's third fallback binds to the
// origin of the FIRST request in the capture — here a third-party CDN
// asset — rather than the real API host that appears later. Every genuine
// API endpoint on that different host is then, by the SEC-BE-001 gate's own
// logic, indistinguishable from an attacker-controlled cross-origin
// candidate, and is silently skipped. Before this PR's gate existed, that
// endpoint would have been probed; this test documents the tradeoff the gate
// introduces so a future change to ResolveTargetOrigin's fallback order is
// caught here rather than discovered as a silent regression in the field.
func TestClassifyProbeGenerate_MixedOriginWithoutTargetURLSkipsRealAPI(t *testing.T) {
	cdn, cdnHits := thirdPartyAssetServer(t)
	api, apiHits := countingAPIServer(t)

	// CDN asset first (mimics import ordering, where the capture's first
	// entry need not be the app's own page), the real API host after it.
	requests := []crawl.ObservedRequest{
		apiRequest(cdn.URL + "/analytics.js"),
		apiRequest(api.URL + "/api/v1/accounts"),
	}
	require.Equal(t, cdn.URL, crawl.ResolveTargetOrigin("", requests),
		"precondition: the resolved origin must be the CDN's, not the API host's")

	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		Warnings:     &warnings,
	})
	require.NoError(t, err)

	assert.Zero(t, atomic.LoadInt32(apiHits),
		"without --target-url, the real API host is misresolved as cross-origin relative to the CDN and must be skipped (documents the hazard)")
	// The gate prints the candidate's ORIGIN, not its full rawURL (see
	// newCrossOriginValidator's doc comment), so api.URL -- which is itself
	// exactly "scheme://host" with no path -- is what appears here, quoted.
	// This is also the sanitization pin for the gate's per-URL skip warning:
	// mutating crawl.SanitizeForLog to `return s` drops the surrounding quote
	// characters and fails this assertion.
	assert.Contains(t, warnings.String(), `skipping cross-origin candidates for "`+api.URL+`"`,
		"the origin is quoted because SEC-BE-002 runs it through crawl.SanitizeForLog")
	assert.Contains(t, warnings.String(), cdn.URL,
		"the one-time derived-origin warning must name the (wrongly) derived CDN origin so the operator can see why")
	assert.Zero(t, atomic.LoadInt32(cdnHits),
		"the CDN server must never actually receive a request (TEST-006): exclusion happens at "+
			"classification time via apiRequest's JSON content-type and the .js static-asset filter")
}

// TestClassifyProbeGenerate_DerivedOriginWarningEscapesBidiOverride pins the
// second half of TEST-008/SEC-BE-002: warnDerivedProbeOrigin must run the
// DERIVED origin through crawl.SanitizeForLog, not just the per-URL skip
// warning's rawURL (already pinned by
// TestClassifyProbeGenerate_MixedOriginWithoutTargetURLSkipsRealAPI's quoted
// api.URL assertion). Removing that wrap survives every other test in this
// file because none of them derive an origin containing an escape-worthy
// byte.
//
// The derived origin CAN carry such a byte: crawl.ResolveTargetOrigin's
// fallback loop feeds the first request's raw URL through originOf, which
// calls url.Parse then u.Hostname() — net/url rejects literal ASCII control
// bytes (0x00-0x1F, 0x7F) outright ("invalid control character in URL"), but
// does NOT reject a bidi override rune (U+202E) in the host, and
// u.Hostname()/strings.ToLower leave it untouched. So a mixed-origin capture
// whose first entry's host contains U+202E produces exactly this targetOrigin
// (verified empirically via net/url before writing this test), mirroring
// pkg/crawl/jsreplay_test.go's "sanitizeForLog neutralizes control bytes in
// the origin" subtest for warnDerivedOrigin's identical wrap.
func TestClassifyProbeGenerate_DerivedOriginWarningEscapesBidiOverride(t *testing.T) {
	api, apiHits := countingAPIServer(t)

	// bidiHostURL is never dialed: it is excluded from classification by the
	// same apiRequest(".js" + JSON content-type) mechanism
	// thirdPartyAssetServer's doc comment explains, and it occupies only the
	// "first request" slot so crawl.ResolveTargetOrigin's fallback derives its
	// (unreachable, bidi-bearing) origin instead of api's.
	const bidiHostURL = "http://evil\u202e.example.test"
	requests := []crawl.ObservedRequest{
		apiRequest(bidiHostURL + "/analytics.js"),
		apiRequest(api.URL + "/api/v1/accounts"),
	}
	derivedOrigin := crawl.ResolveTargetOrigin("", requests)
	require.Contains(t, derivedOrigin, "\u202e",
		"precondition: the derived origin must carry the raw bidi override byte")

	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		Warnings:     &warnings,
	})
	require.NoError(t, err)

	assert.Zero(t, atomic.LoadInt32(apiHits),
		"precondition: api must be cross-origin relative to the derived bidi origin, so it's never dialed")
	assert.NotContains(t, warnings.String(), "\u202e",
		"the derived-origin warning must escape the bidi override byte, not emit it raw (SEC-BE-002)")
	assert.Contains(t, warnings.String(), `evil\u202e.example.test`,
		"the derived-origin warning must still name the (escaped) derived origin so the operator can see why")
}

// TestClassifyProbeGenerate_DerivedOriginWarningAbsentWhenTargetURLSet is the
// companion negative case: when --target-url IS supplied, the origin was
// chosen by the operator, not derived, so the one-time derived-origin
// warning must not fire (only the ordinary per-URL skip warning, if any,
// would appear).
func TestClassifyProbeGenerate_DerivedOriginWarningAbsentWhenTargetURLSet(t *testing.T) {
	target, hits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{apiRequest(target.URL + "/api/v1/users")}

	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		TargetURL:    target.URL,
		Warnings:     &warnings,
	})
	require.NoError(t, err)

	assert.Positive(t, atomic.LoadInt32(hits))
	assert.NotContains(t, warnings.String(), "not set",
		"the derived-origin warning must not fire when --target-url was explicitly supplied")
}

// TestClassifyProbeGenerate_AllSameOriginNoTargetURLStaysQuiet is the direct
// regression test for the SEC-BE-001 nit review finding's laziness fix: the
// derived-origin warning used to fire unconditionally, once per
// ClassifyProbeGenerate invocation, before any candidate was even evaluated
// -- so the ordinary single-origin `generate` without --target-url (an
// all-same-origin capture, the common case) printed "endpoints outside this
// origin will be skipped" even though nothing ever was, eroding the signal
// the warning exists to carry. --target-url is deliberately left unset here
// so targetOrigin is DERIVED from the capture (the precondition for the
// warning to even be eligible to fire), and every candidate is same-origin
// relative to that derived origin, so nothing is ever rejected as
// cross-origin -- the warning must therefore never fire at all.
//
// Mutation-verified against the pre-fix behavior: moving the
// warnDerivedProbeOrigin call back to pipeline.go's eager call site (before
// the `if !opts.AllowCrossOriginProbe` branch's validator is even
// constructed) makes this test fail, since the warning would then print
// unconditionally regardless of whether any candidate was actually skipped.
func TestClassifyProbeGenerate_AllSameOriginNoTargetURLStaysQuiet(t *testing.T) {
	target, hits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{apiRequest(target.URL + "/api/v1/users")}
	require.Equal(t, target.URL, crawl.ResolveTargetOrigin("", requests),
		"precondition: with no --target-url, the origin must be derived from the capture's only request")

	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		// TargetURL deliberately left unset: the origin is derived, not chosen.
		Warnings: &warnings,
	})
	require.NoError(t, err)

	assert.Positive(t, atomic.LoadInt32(hits), "the sole, same-origin candidate must still be probed")
	assert.Empty(t, warnings.String(),
		"an all-same-origin capture must stay completely quiet: nothing was skipped, "+
			"so neither the derived-origin warning nor a per-origin skip warning may print")
}

// TestClassifyProbeGenerate_MixedOriginWithTargetURLProbesRealAPI is the
// companion to TestClassifyProbeGenerate_MixedOriginWithoutTargetURLSkipsRealAPI:
// the same mixed-origin capture, but with --target-url pinned to the real API
// host. crawl.ResolveTargetOrigin's explicit-targetURL branch now takes
// precedence over the CDN-first fallback, so the genuine API endpoint is
// recognized as same-origin and probed — the documented remedy for the
// hazard the previous test pins.
func TestClassifyProbeGenerate_MixedOriginWithTargetURLProbesRealAPI(t *testing.T) {
	cdn, cdnHits := thirdPartyAssetServer(t)
	api, apiHits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{
		apiRequest(cdn.URL + "/analytics.js"),
		apiRequest(api.URL + "/api/v1/accounts"),
	}

	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		TargetURL:    api.URL,
	})
	require.NoError(t, err)

	assert.Positive(t, atomic.LoadInt32(apiHits),
		"--target-url pinned to the real API host must make its endpoints same-origin and probed")
	assert.Zero(t, atomic.LoadInt32(cdnHits),
		"the CDN server must never actually receive a request (TEST-006)")
}

// TestClassifyProbeGenerate_UnusableTargetURLStillWarns is the SEC-BE-002
// regression test, UPDATED for SEC-BE-001's fail-closed ResolveTargetOrigin
// (LAB-4992 review). Before SEC-BE-001, a non-empty but UNUSABLE --target-url
// (unparseable, or parseable with no host) made crawl.ResolveTargetOrigin
// silently fall through its fallback chain to an origin derived from the
// capture (here, the CDN's), so this test originally asserted the
// "derived origin %s from the capture" warning variant and that only the real
// API host (cross-origin relative to that derived CDN origin) was skipped.
//
// ResolveTargetOrigin now fails closed for this exact input instead of
// falling through (an un-canonicalizable EXPLICIT target must never let
// bundle-supplied capture content pick the origin — see its doc comment), so
// targetOrigin is now "" here too, same as the opts.TargetURL == "" case: the
// warning fires the OTHER variant ("no usable origin could be derived from
// the capture; every probe candidate is being rejected"), and EVERY
// candidate — not just the real API host — is rejected as a result. This is
// a stricter (more secure), not weaker, outcome.
//
// The companion "a usable TargetURL must not warn" case is already covered by
// TestClassifyProbeGenerate_DerivedOriginWarningAbsentWhenTargetURLSet; not
// duplicated here.
func TestClassifyProbeGenerate_UnusableTargetURLStillWarns(t *testing.T) {
	cdn, cdnHits := thirdPartyAssetServer(t)
	api, apiHits := countingAPIServer(t)

	requests := []crawl.ObservedRequest{
		apiRequest(cdn.URL + "/analytics.js"),
		apiRequest(api.URL + "/api/v1/accounts"),
	}
	require.Equal(t, "", crawl.ResolveTargetOrigin("not a url", nil),
		"precondition: \"not a url\" must not itself resolve to a usable origin")
	require.Equal(t, "", crawl.ResolveTargetOrigin("not a url", requests),
		"precondition (SEC-BE-001): a non-empty but un-canonicalizable TargetURL must fail closed "+
			"rather than fall through to the capture-derived CDN origin")

	var warnings bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
		TargetURL:    "not a url",
		Warnings:     &warnings,
	})
	require.NoError(t, err)

	assert.Zero(t, atomic.LoadInt32(apiHits),
		"an unusable --target-url must not pin the real API host as same-origin")
	assert.Zero(t, atomic.LoadInt32(cdnHits))
	// The exact wording changed (SEC-BE-001 nit review finding): the
	// operator-facing string no longer names the internal finding ID
	// "SEC-BE-001", which meant nothing outside this repo's review history.
	assert.Contains(t, warnings.String(), "no usable origin could be derived",
		"a non-empty but unusable --target-url must still trigger the derived-origin warning -- now the "+
			"'no usable origin' variant, since ResolveTargetOrigin fails closed instead of deriving one")
}
