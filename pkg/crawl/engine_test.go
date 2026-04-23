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
		// browser intentionally nil — the error path must return before any
		// CDP call happens. If a future refactor accidentally advances past
		// Push before the guard, this test will panic on nil-browser deref
		// rather than silently passing.
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
	if !strings.Contains(err.Error(), "--dangerous-allow-private") {
		t.Errorf("Crawl error %q should name the remediation flag (--dangerous-allow-private) so operators know what to do", err)
	}
}
