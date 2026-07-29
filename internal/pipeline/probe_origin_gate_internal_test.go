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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewCrossOriginValidator_SameOriginDelegatesToBase is a white-box
// complement to TestClassifyProbeGenerate_SameOriginLoopbackRejectedWithoutAllowPrivate
// (TEST-003). That black-box test cannot, by itself, prove the same-origin
// arm's `return base(rawURL)` line is what rejects a loopback candidate,
// because probe.Config's Dialer independently re-checks the identical
// private-IP predicate at connect time (defense-in-depth) — so a same-origin
// loopback target is rejected over the wire whether or not `base` is ever
// actually consulted. This test calls newCrossOriginValidator directly with
// an injected base that returns a distinguishable sentinel error for EVERY
// input, sidestepping the network entirely: if the same-origin arm stopped
// calling base (e.g. mutated to `return nil`), the returned error would be
// nil instead of the sentinel, and this test would fail.
func TestNewCrossOriginValidator_SameOriginDelegatesToBase(t *testing.T) {
	sentinel := errors.New("sentinel: base was consulted")
	base := func(string) error { return sentinel }

	validate := newCrossOriginValidator(base, "http://target.example:80", false, nil)

	err := validate("http://target.example/api/v1/x")
	require.Error(t, err)
	assert.Same(t, sentinel, err, "the same-origin arm must return exactly base's error, proving it delegates rather than short-circuiting")
}

// TestNewCrossOriginValidator_SameOriginAllowsWhenBaseAllows is a cheap,
// white-box positive control: when base has no objection, the same-origin arm
// must not introduce a rejection of its own. It has NO independent kill of its
// own beyond what TestClassifyProbeGenerate_SameOriginCandidateIsProbed
// (probe_origin_gate_test.go) already covers black-box, end-to-end, through
// the real ClassifyProbeGenerate call site (TEST-001 review finding) --
// mutating the same-origin arm to always return an error would fail both.
// Kept (rather than deleted) because it isolates the same-origin arm from
// probe.RunStrategies/network entirely, making a future failure here cheaper
// to diagnose than tracing back through the black-box test.
func TestNewCrossOriginValidator_SameOriginAllowsWhenBaseAllows(t *testing.T) {
	base := func(string) error { return nil }

	validate := newCrossOriginValidator(base, "http://target.example:80", false, nil)

	err := validate("http://target.example/api/v1/x")
	assert.NoError(t, err)
}

// TestNewFullURLValidator_NilBaseFallsBackToProbeValidateProbeURL is the
// white-box regression test for the TEST-001 finding: newFullURLValidator is
// now the FIRST wrapper applied at the pipeline.go call site, so in the
// shipped default configuration (AllowPrivate=false, so probe.DefaultConfig()
// leaves cfg.URLValidator nil) it is THIS function's nil-base fallback -- not
// newCrossOriginValidator's, which no longer has one (see its doc comment) --
// that installs the real SSRF check. A nil base must fall back to the REAL
// probe.ValidateProbeURL -- not an unconditional allow -- so a candidate
// whose host is a private/loopback IP is still rejected. If that fallback
// were replaced with a no-op, this call would return nil instead of an
// error. This test replaces
// TestNewCrossOriginValidator_NilCfgValidatorFallsBackToProbeValidateProbeURL,
// which pinned the identical fallback on newCrossOriginValidator after it had
// become dead code from the production call site.
//
// TEST-002: the URL is both loopback (rejected by the SSRF fallback) AND
// well-formed with no userinfo (so the parse-time gate above it would NOT
// reject it), so the assertion below can only be satisfied by the fallback
// branch actually being consulted -- not incidentally by the parse-time gate
// rejecting first, which the plain require.Error alone could not rule out.
func TestNewFullURLValidator_NilBaseFallsBackToProbeValidateProbeURL(t *testing.T) {
	validate := newFullURLValidator(nil)

	err := validate("http://127.0.0.1:9/api/v1/x")
	require.Error(t, err, "a nil base must fall back to probe.ValidateProbeURL, "+
		"which rejects a loopback candidate")
	assert.NotContains(t, err.Error(), "parse-time validation",
		"the error must come from the SSRF fallback branch, not the parse-time gate")
}
