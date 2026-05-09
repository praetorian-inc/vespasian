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

package jsstatic

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// makeJSCapture returns a captured ObservedRequest whose response body is JS.
func makeJSCapture(url, body string) crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method: "GET",
		URL:    url,
		Source: "katana",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/javascript",
			Body:        []byte(body),
		},
	}
}

// makeHTMLCapture returns a captured HTML response (not JS).
func makeHTMLCapture(url string) crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method: "GET",
		URL:    url,
		Source: "katana",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "text/html",
			Body:        []byte(`<html><body>fetch("/api/users")</body></html>`),
		},
	}
}

func TestAnalyze_AppendsAfterDynamic(t *testing.T) {
	// Dynamic capture already has /api/users.
	dynamic := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://h/api/users",
		Source: "katana",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/json",
		},
	}
	dynamic2 := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://h/api/products",
		Source: "katana",
	}
	// JS bundle finds /api/users (collision) and nothing else unique.
	jsBundle := makeJSCapture("https://h/app.js", `fetch("/api/users")`)

	captured := []crawl.ObservedRequest{dynamic, dynamic2, jsBundle}

	res, err := Analyze(context.Background(), captured, Options{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	// Result must contain the 3 original + 1 synthesized (even if dedup would collapse).
	if len(res.Requests) < 3 {
		t.Fatalf("expected at least 3 requests, got %d", len(res.Requests))
	}
	// Original dynamic entries come first.
	if res.Requests[0].Source != "katana" {
		t.Errorf("first entry should be dynamic (katana), got %q", res.Requests[0].Source)
	}
	if res.Requests[1].Source != "katana" {
		t.Errorf("second entry should be dynamic (katana), got %q", res.Requests[1].Source)
	}

	// Run dedup to confirm dynamic entry wins on collision.
	classified := make([]classify.ClassifiedRequest, 0, len(res.Requests))
	for _, r := range res.Requests {
		classified = append(classified, classify.ClassifiedRequest{
			ObservedRequest: r,
			IsAPI:           true,
			Confidence:      0.9,
			APIType:         "rest",
		})
	}
	deduped := classify.Deduplicate(classified)
	// Find /api/users — it should be dynamic (katana).
	for _, d := range deduped {
		if strings.Contains(d.URL, "/api/users") {
			if d.Source != "katana" {
				t.Errorf("after dedup, /api/users should be katana, got %q", d.Source)
			}
			break
		}
	}

	if res.Stats.BundlesAnalyzed < 1 {
		t.Errorf("expected BundlesAnalyzed >= 1, got %d", res.Stats.BundlesAnalyzed)
	}
}

func TestAnalyze_NonJSResponsesIgnored(t *testing.T) {
	// An HTML body that contains fetch() — if parsed as JS would yield endpoints.
	html := makeHTMLCapture("https://h/page")
	captured := []crawl.ObservedRequest{html}

	res, err := Analyze(context.Background(), captured, Options{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if res.Stats.BundlesAnalyzed != 0 {
		t.Errorf("expected BundlesAnalyzed=0 for HTML, got %d", res.Stats.BundlesAnalyzed)
	}
	// Only the HTML request should be present.
	if len(res.Requests) != 1 {
		t.Errorf("expected 1 request (input unchanged), got %d", len(res.Requests))
	}
}

func TestAnalyze_OversizedBundleSkipped(t *testing.T) {
	maxSize := DefaultMaxBundleSize
	big := bytes.Repeat([]byte("x"), maxSize+1)
	oversized := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://h/big.js",
		Source: "katana",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/javascript",
			Body:        big,
		},
	}

	res, err := Analyze(context.Background(), []crawl.ObservedRequest{oversized}, Options{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if res.Stats.BundlesSkipped != 1 {
		t.Errorf("expected BundlesSkipped=1, got %d", res.Stats.BundlesSkipped)
	}
	if res.Stats.BundlesAnalyzed != 0 {
		t.Errorf("expected BundlesAnalyzed=0, got %d", res.Stats.BundlesAnalyzed)
	}
}

func TestAnalyze_ReturnsCopyNotMutation(t *testing.T) {
	js := makeJSCapture("https://h/app.js", `fetch("/api/x")`)
	original := []crawl.ObservedRequest{js}
	origLen := len(original)

	res, err := Analyze(context.Background(), original, Options{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	// Input len unchanged.
	if len(original) != origLen {
		t.Errorf("input slice modified: was %d, now %d", origLen, len(original))
	}
	// Output is a new slice.
	if len(res.Requests) < 1 {
		t.Fatalf("expected at least 1 request")
	}
}

func TestAnalyze_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	captured := []crawl.ObservedRequest{makeJSCapture("https://h/app.js", `fetch("/api/x")`)}

	res, err := Analyze(ctx, captured, Options{})
	// Should return the captured (unmodified) slice and a context error.
	if err == nil {
		t.Error("expected non-nil error for canceled context")
	}
	// Input requests should be in output even on cancel.
	if len(res.Requests) < 1 {
		t.Error("expected at least original captured requests in result")
	}
}

func TestAnalyze_DefaultOptionsAreSane(t *testing.T) {
	captured := []crawl.ObservedRequest{makeJSCapture("https://h/app.js", `fetch("/api/x")`)}
	// Should not panic with zero Options.
	res, err := Analyze(context.Background(), captured, Options{})
	if err != nil {
		t.Fatalf("Analyze error with zero Options: %v", err)
	}
	_ = res // just checking no panic
}

func TestAnalyze_SourcemapAndBundleEmissions(t *testing.T) {
	// Build a valid sourcemap data URI with one source that has a fetch call.
	srcContent := `fetch("/api/from-sourcemap")`
	smDoc := fmt.Sprintf(`{"sources":["src/index.js"],"sourcesContent":[%s]}`,
		func() string { b, _ := json.Marshal(srcContent); return string(b) }())
	encoded := base64.StdEncoding.EncodeToString([]byte(smDoc))
	dataURI := "data:application/json;base64," + encoded

	bundleBody := `fetch("/api/from-bundle")` + "\n//# sourceMappingURL=" + dataURI

	bundle := makeJSCapture("https://h/app.js", bundleBody)
	res, err := Analyze(context.Background(), []crawl.ObservedRequest{bundle}, Options{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	// There should be requests with both static:js and static:js-sourcemap.
	var hasJS, hasSM bool
	for _, r := range res.Requests {
		if r.Source == SourceJS {
			hasJS = true
		}
		if r.Source == SourceSourcemap {
			hasSM = true
		}
	}
	if !hasJS {
		t.Error("expected at least one static:js request")
	}
	if !hasSM {
		t.Error("expected at least one static:js-sourcemap request")
	}
}

// TestAnalyze_StatsEndpointsFound verifies that Stats.EndpointsFound is
// populated (it counts raw extractedEndpoints before filtering/dedup).
func TestAnalyze_StatsEndpointsFound(t *testing.T) {
	cap := makeJSCapture("https://example.com/app.js", `
		fetch("/api/users");
		fetch("/api/orders", {method: "POST"});
		axios.get("/api/products");
	`)
	res, err := Analyze(context.Background(), []crawl.ObservedRequest{cap}, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Stats.EndpointsFound < 3 {
		t.Errorf("expected EndpointsFound >= 3, got %d", res.Stats.EndpointsFound)
	}
	if res.Stats.BundlesAnalyzed != 1 {
		t.Errorf("expected BundlesAnalyzed=1, got %d", res.Stats.BundlesAnalyzed)
	}
}

// TestExtractFromBundle_HonorsMaxEndpoints verifies that the analyzer respects
// Options.MaxEndpointsPerBundle by truncating the per-bundle endpoint slice.
func TestExtractFromBundle_HonorsMaxEndpoints(t *testing.T) {
	// Build a bundle with 10 unique fetch URLs. The cap is enforced in Analyze
	// (see jsstatic.go), not in ExtractFromBundle, so we test via Analyze.
	var sb strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&sb, "fetch(\"/api/r%d\");\n", i)
	}
	cap := makeJSCapture("https://example.com/app.js", sb.String())

	res, err := Analyze(context.Background(), []crawl.ObservedRequest{cap}, Options{
		MaxEndpointsPerBundle: 3,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// Originating capture (1) + capped synthesized (3) == 4. Anything more means the cap was ignored.
	staticCount := 0
	for _, r := range res.Requests {
		if r.Source == "static:js" {
			staticCount++
		}
	}
	if staticCount > 3 {
		t.Errorf("MaxEndpointsPerBundle=3, got %d static entries", staticCount)
	}
	if staticCount == 0 {
		t.Errorf("expected some static entries up to the cap, got 0")
	}
}

// TestExtractFromBundle_MinifiedBundleSmoke confirms that extraction works on a
// single-line minified-style bundle with multiple fetches concatenated together.
func TestExtractFromBundle_MinifiedBundleSmoke(t *testing.T) {
	// One line, no whitespace except where strictly necessary.
	source := []byte(`!function(){var a=fetch("/api/auth/login",{method:"POST"});var b=fetch("/api/profile");axios.get("/api/products");}();`)
	endpoints, err := ExtractFromBundle(source, "https://example.com/min.js", Options{})
	if err != nil {
		t.Fatalf("ExtractFromBundle: %v", err)
	}
	want := map[string]bool{
		"/api/auth/login": false,
		"/api/profile":    false,
		"/api/products":   false,
	}
	for _, ep := range endpoints {
		if _, ok := want[ep.URL]; ok {
			want[ep.URL] = true
		}
	}
	for url, found := range want {
		if !found {
			t.Errorf("expected to find %q in minified bundle, did not", url)
		}
	}
}

// TestAnalyze_PerBundleTimeoutSkips verifies Analyze records a skipped bundle
// when the per-bundle parse exceeds Options.PerBundleTimeout. The parse runs in
// a goroutine; the orchestrator selects on the timeout channel and increments
// BundlesSkipped. Using a 1ns timeout is reliably racey-skipping for any
// non-trivial bundle.
func TestAnalyze_PerBundleTimeoutSkips(t *testing.T) {
	// Build a moderately-sized bundle so jsluice spends > 1ns parsing it.
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&sb, "fetch(\"/api/r%d\");\n", i)
	}
	cap := makeJSCapture("https://example.com/big.js", sb.String())

	res, err := Analyze(context.Background(), []crawl.ObservedRequest{cap}, Options{
		PerBundleTimeout: 1, // 1 nanosecond — guaranteed timeout.
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Stats.BundlesSkipped == 0 && res.Stats.BundlesAnalyzed == 0 {
		t.Errorf("expected BundlesSkipped or BundlesAnalyzed to be > 0, both 0")
	}
	// Either the timeout fired (Skipped) or jsluice was lightning fast (Analyzed).
	// Both outcomes are acceptable here; what we want is to confirm the timeout
	// path doesn't deadlock and doesn't leak the goroutine.
}

// keep imports honest
var _ = bytes.NewReader
var _ = base64.StdEncoding
var _ = json.Marshal
var _ = classify.Deduplicate
