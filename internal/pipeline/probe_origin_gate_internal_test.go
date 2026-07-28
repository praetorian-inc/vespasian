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

	validate := newCrossOriginValidator(base, "http://target.example:80", nil)

	err := validate("http://target.example/api/v1/x")
	require.Error(t, err)
	assert.Same(t, sentinel, err, "the same-origin arm must return exactly base's error, proving it delegates rather than short-circuiting")
}

// TestNewCrossOriginValidator_SameOriginAllowsWhenBaseAllows is the positive
// companion: when base has no objection, the same-origin arm must not
// introduce a rejection of its own.
func TestNewCrossOriginValidator_SameOriginAllowsWhenBaseAllows(t *testing.T) {
	base := func(string) error { return nil }

	validate := newCrossOriginValidator(base, "http://target.example:80", nil)

	err := validate("http://target.example/api/v1/x")
	assert.NoError(t, err)
}

// TestNewCrossOriginValidator_NilCfgValidatorFallsBackToProbeValidateProbeURL
// is the white-box regression test for the TEST-003 finding's second half:
// pipeline.go's `baseValidator = probe.ValidateProbeURL` fallback (moved into
// this function so it is directly testable — see newCrossOriginValidator's
// doc comment for why a black-box network test cannot distinguish this
// mutation from cfg.Dialer's own redundant SSRF check). A nil cfgValidator
// (the default, AllowPrivate=false configuration) must fall back to the REAL
// probe.ValidateProbeURL — not an unconditional allow — so a same-origin
// candidate whose host is a private/loopback IP is still rejected. If that
// fallback were replaced with a no-op (mutation (b)), this call would return
// nil instead of an error.
func TestNewCrossOriginValidator_NilCfgValidatorFallsBackToProbeValidateProbeURL(t *testing.T) {
	validate := newCrossOriginValidator(nil, "http://127.0.0.1:9", nil)

	err := validate("http://127.0.0.1:9/api/v1/x")
	require.Error(t, err, "a nil cfgValidator must fall back to probe.ValidateProbeURL, "+
		"which rejects a same-origin loopback candidate")
}
