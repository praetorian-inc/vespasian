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

package crawl

import (
	"context"
	"strings"
	"testing"
)

// TestRodEngine_Crawl_SeedRejectedByFrontierReturnsError covers LAB-2438.
//
// Before this fix, when the frontier rejected the seed (e.g., the seed host
// was private and allowPrivate=false), engine.Crawl pushed zero entries and
// then blocked in wg.Wait() until all workers saw an empty frontier, returning
// nil with no captures — the operator got `captured 0 requests` with no error
// and no way to diagnose. The fix makes this condition a hard error that
// names the seed and points at `--dangerous-allow-private`.
//
// This test constructs a frontier with a scope predicate that rejects every
// URL, calls Crawl, and asserts a non-nil error is returned without the
// engine ever touching the (nil) browser.
func TestRodEngine_Crawl_SeedRejectedByFrontierReturnsError(t *testing.T) {
	// rejectAll mirrors the private-seed + SSRF rejection case without
	// requiring the real scopeChecker wiring — Push just asks for a
	// func(string) bool, and we control its answer.
	rejectAll := func(string) bool { return false }

	e := &rodEngine{
		// AC #3: nil browser is deliberate — see LAB-2438. The error path must
		// return before any CDP call happens. If a future refactor accidentally
		// advances past Push before the guard, this test will panic on a
		// nil-browser deref (at e.browser.Page() in visitPage, engine.go) rather
		// than silently passing.
		browser: nil,
		opts: engineOptions{
			Concurrency: 1,
			MaxPages:    10,
			MaxDepth:    2,
			ScopeCheck:  rejectAll,
		},
		frontier: newURLFrontier(2, rejectAll),
	}

	err := e.Crawl(context.Background(), "http://localhost:9000", func(ObservedRequest) {
		t.Fatal("onResult must not be called when the seed is rejected")
	})
	if err == nil {
		t.Fatal("Crawl returned nil error on rejected seed; expected a descriptive error")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("Crawl error %q should mention 'rejected'; prior bug was a silent empty-frontier exit", err)
	}
	if !strings.Contains(err.Error(), "http://localhost:9000") {
		t.Errorf("Crawl error %q should echo the seed URL for operator diagnosis", err)
	}
	if !strings.Contains(err.Error(), flagDangerousAllowPrivate) {
		t.Errorf("Crawl error %q should name the remediation flag (%s) so operators know what to do", err, flagDangerousAllowPrivate)
	}
	// Pin the load-bearing operator-facing clauses so a refactor that drops
	// either the diagnostic breakdown or the private-host enumeration fails
	// the test instead of silently degrading the error message.
	if !strings.Contains(err.Error(), "scope, SSRF, or parse") {
		t.Errorf("Crawl error %q should include the '(scope, SSRF, or parse)' diagnostic breakdown so operators know why the seed was rejected", err)
	}
	if !strings.Contains(err.Error(), "private host") {
		t.Errorf("Crawl error %q should include the 'private host' enumeration so operators recognize the common-case cause", err)
	}
}

// TestRodEngine_Crawl_SeedAcceptedDoesNotReturnRejectionError covers LAB-2438
// AC #2: with --dangerous-allow-private (modeled here as an accept-all scope
// predicate) the Crawl entry-point must NOT emit the
// "seed URL rejected by frontier" error. Without this test the happy path is
// only pinned by the live-test harness / integration-tagged tests; the default
// suite had no tripwire for a regression that starts rejecting valid seeds.
//
// We cannot run the full crawl in a unit test (there is no browser), so we
// invoke Crawl with Concurrency=0 — newRodEngine normally bumps that to
// DefaultConcurrency, but we bypass newRodEngine here and construct rodEngine
// directly. With Concurrency=0 no worker goroutines launch, wg.Wait() returns
// immediately, and Crawl returns ctx.Err() (nil for context.Background()).
// The only way to hit the rejection error is for Push to return 0; with an
// accept-all predicate Push returns 1, so the rejection error is not emitted.
func TestRodEngine_Crawl_SeedAcceptedDoesNotReturnRejectionError(t *testing.T) {
	acceptAll := func(string) bool { return true }

	e := &rodEngine{
		// Same nil-browser rationale as the rejection test above, and it is
		// load-bearing here: Concurrency=0 means no workers launch, so we
		// never reach visitPage's e.browser.Page() call. If someone changes
		// Crawl to launch a worker regardless of Concurrency, this test will
		// panic on nil-browser deref instead of silently hanging.
		browser: nil,
		opts: engineOptions{
			Concurrency: 0,
			MaxPages:    10,
			MaxDepth:    2,
			ScopeCheck:  acceptAll,
		},
		frontier: newURLFrontier(2, acceptAll),
	}

	err := e.Crawl(context.Background(), "http://example.com", func(ObservedRequest) {})
	if err != nil && strings.Contains(err.Error(), "seed URL rejected by frontier") {
		t.Fatalf("Crawl returned rejection error %q on accept-all predicate; AC #2 requires the happy path to not trigger the rejection path", err)
	}
}

// TestRodEngine_Crawl_SeedRejectionRedactsUserinfo covers the follow-up to
// LAB-2438: an operator may paste a credentialed seed URL (e.g.
// http://user:pass@internal.corp) and forget flagDangerousAllowPrivate. The
// rejection error is written to stderr by kong's FatalIfErrorf and can land in
// shell history, terminal scrollback, or CI logs. The error message therefore
// must not echo the password (or username) back to the operator.
func TestRodEngine_Crawl_SeedRejectionRedactsUserinfo(t *testing.T) {
	rejectAll := func(string) bool { return false }

	e := &rodEngine{
		browser: nil,
		opts: engineOptions{
			Concurrency: 1, MaxPages: 10, MaxDepth: 2, ScopeCheck: rejectAll,
		},
		frontier: newURLFrontier(2, rejectAll),
	}

	seed := "http://admin:s3cret@10.0.0.5:8080/path" //nolint:gosec // G101: intentional test credential used to verify redactSeedURL strips userinfo from error messages
	err := e.Crawl(context.Background(), seed, func(ObservedRequest) {
		t.Fatal("onResult must not be called when the seed is rejected")
	})
	if err == nil {
		t.Fatal("Crawl returned nil error on rejected credentialed seed; expected a descriptive error")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("Crawl error %q MUST NOT echo the seed password; it could land in shell history or CI logs", err)
	}
	if strings.Contains(err.Error(), "admin") {
		t.Errorf("Crawl error %q MUST NOT echo the seed username; redactSeedURL is expected to strip the full userinfo block", err)
	}
	// The rest of the URL (host, port, path) is operator-supplied context and
	// must still be present so the operator can identify which seed failed.
	if !strings.Contains(err.Error(), "10.0.0.5:8080") {
		t.Errorf("Crawl error %q should still echo the host:port after redaction", err)
	}
	if !strings.Contains(err.Error(), "/path") {
		t.Errorf("Crawl error %q should still echo the path after redaction", err)
	}
}

// TestRedactSeedURL table-drives the redaction helper directly so regressions
// in url.Parse handling (empty URLs, malformed, no userinfo) are caught
// independently of the Crawl integration above.
func TestRedactSeedURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no userinfo", "http://example.com/x", "http://example.com/x"},
		{"user+password", "http://u:p@example.com:443/x?q=1", "http://example.com:443/x?q=1"},
		{"user only", "http://u@example.com/x", "http://example.com/x"},
		{"empty password", "http://u:@example.com/x", "http://example.com/x"},
		// IPv6 literal uses bracket notation in the authority; url.Parse
		// round-trips the brackets so the host:port form is preserved.
		{"ipv6 with userinfo", "http://u:p@[::1]:8080/x", "http://[::1]:8080/x"}, //nolint:gosec // G101: intentional test credential used to verify IPv6 userinfo redaction
		{"empty string", "", ""},
		// url.Parse fails on unknown scheme syntax, but the string has no
		// "@" so we fall through to the raw-return path. Operators still
		// get an actionable message without risking credential leak.
		{"malformed no userinfo returned as-is", "://not a url", "://not a url"},
		// url.Parse fails (invalid percent-escape in userinfo) AND the raw
		// string contains "@", so we fail closed: the placeholder is emitted
		// instead of echoing "admin:se%zz@host/path" with credentials.
		{"malformed with userinfo redacts to placeholder", "http://admin:se%zz@host/path", unparseableURLPlaceholder}, //nolint:gosec // G101: intentional malformed test credential used to verify fail-closed redaction
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactSeedURL(tc.in)
			if got != tc.want {
				t.Errorf("redactSeedURL(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}
