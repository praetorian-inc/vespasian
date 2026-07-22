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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/httpx"
)

// formsAndJSCapture returns one HTML page carrying a <form> and one JS bundle
// carrying a fetch() call, so Augment exercises both the static-HTML forms
// stage and the JS-static stage.
func formsAndJSCapture() []crawl.ObservedRequest {
	return []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/login",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body: []byte(`<html><body>` +
					`<form method="POST" action="/api/login">` +
					`<input name="email" type="email">` +
					`</form></body></html>`),
			},
		},
		{
			Method: "GET",
			URL:    "https://example.com/app.js",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        []byte(`fetch("/api/users")`),
			},
		},
	}
}

// TestAugment_FormsBeforeJSStatic pins the canonical order: static:html entries
// must precede static:js entries so classify.Deduplicate first-write-wins keeps
// form-derived signals on collisions.
func TestAugment_FormsBeforeJSStatic(t *testing.T) {
	enriched := pipeline.Augment(context.Background(), formsAndJSCapture(), pipeline.AugmentOptions{
		AnalyzeJS:    true,
		AllowPrivate: true,
	})

	firstHTML, firstJS := -1, -1
	for i, r := range enriched {
		if firstHTML == -1 && r.Source == "static:html" {
			firstHTML = i
		}
		if firstJS == -1 && r.Source == "static:js" {
			firstJS = i
		}
	}
	require.NotEqual(t, -1, firstHTML, "expected at least one static:html entry")
	require.NotEqual(t, -1, firstJS, "expected at least one static:js entry")
	assert.Less(t, firstHTML, firstJS, "static:html must precede static:js")
}

// TestAugment_DisabledJS_KeepsFormsAugmentation verifies that the forms stage
// always runs and the JS stage short-circuits when AnalyzeJS is false.
func TestAugment_DisabledJS_KeepsFormsAugmentation(t *testing.T) {
	enriched := pipeline.Augment(context.Background(), formsAndJSCapture(), pipeline.AugmentOptions{
		AnalyzeJS: false,
	})

	var sawHTML, sawJS bool
	for _, r := range enriched {
		switch r.Source {
		case "static:html":
			sawHTML = true
		case "static:js", "static:js-sourcemap":
			sawJS = true
		}
	}
	assert.True(t, sawHTML, "forms stage must run even when AnalyzeJS=false")
	assert.False(t, sawJS, "JS stage must not run when AnalyzeJS=false")
}

// TestAugment_IdempotencyGuard verifies that when the input already carries a
// static:js source, the JS stage is skipped (no re-analysis, no growth from the
// bundle). The forms stage still runs, but the fixture below has no <form>, so
// the slice must be returned with the same JS-static count.
func TestAugment_IdempotencyGuard(t *testing.T) {
	captured := append(formsAndJSCapture(), crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://example.com/api/users",
		Source: crawl.SourceStaticJS,
	})

	enriched := pipeline.Augment(context.Background(), captured, pipeline.AugmentOptions{
		AnalyzeJS:    true,
		AllowPrivate: true,
	})

	jsCount := 0
	for _, r := range enriched {
		if crawl.IsJSStaticSource(r.Source) {
			jsCount++
		}
	}
	assert.Equal(t, 1, jsCount, "idempotency guard must skip re-analysis: exactly the pre-seeded static:js entry")
}

// TestAugment_VerboseStatusLine verifies that a non-nil Status writer receives
// the js-static stats line.
func TestAugment_VerboseStatusLine(t *testing.T) {
	var buf bytes.Buffer
	pipeline.Augment(context.Background(), formsAndJSCapture(), pipeline.AugmentOptions{
		AnalyzeJS:    true,
		AllowPrivate: true,
		Status:       &buf,
	})
	assert.Contains(t, buf.String(), "js-static:")
	assert.Contains(t, buf.String(), "bundles=")
	assert.Contains(t, buf.String(), "endpoints=")
}

// TestAugment_QuietByDefault verifies that a nil Status writer produces no
// stats output and does not panic.
func TestAugment_QuietByDefault(t *testing.T) {
	enriched := pipeline.Augment(context.Background(), formsAndJSCapture(), pipeline.AugmentOptions{
		AnalyzeJS:    true,
		AllowPrivate: true,
		Status:       nil,
	})
	// Forms + at least one JS entry produced; just assert the call succeeded.
	assert.Greater(t, len(enriched), len(formsAndJSCapture()))
}

// TestAugment_JSErrorIsNonFatal verifies that a JS-analysis error (here a
// pre-canceled context) is non-fatal: the forms-augmented slice is returned and
// no JS-static entries are appended.
func TestAugment_JSErrorIsNonFatal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	enriched := pipeline.Augment(ctx, formsAndJSCapture(), pipeline.AugmentOptions{
		AnalyzeJS:    true,
		AllowPrivate: true,
	})

	for _, r := range enriched {
		assert.False(t, crawl.IsJSStaticSource(r.Source), "no JS-static entries expected when analysis errors")
	}
}

// jsOnlyCapture returns one HTML page and one JS bundle exercising fetch, with
// no <form> element — so only the JS-static stage produces synthetic entries.
// Used by the AnalyzeJS-direct tests (migrated from the CLI helper tests).
func jsOnlyCapture() []crawl.ObservedRequest {
	return []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte(`<html></html>`),
			},
		},
		{
			Method: "GET",
			URL:    "https://example.com/app.js",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        []byte(`fetch("/api/v1/users")`),
			},
		},
	}
}

// TestAnalyzeJS_Enabled_AppendsStaticEntries verifies that AnalyzeJS (the
// JS-only stage CrawlCmd runs at crawl time) hands the captured slice to
// jsstatic.Analyze and returns an enriched slice with static:js entries
// appended after the dynamic prefix (classify.Deduplicate relies on
// first-write-wins, so dynamic entries must stay first). Migrated from the CLI
// runJSAnalysisStage test.
func TestAnalyzeJS_Enabled_AppendsStaticEntries(t *testing.T) {
	captured := jsOnlyCapture()
	out := pipeline.AnalyzeJS(context.Background(), captured, pipeline.AugmentOptions{
		AnalyzeJS:    true,
		AllowPrivate: true,
	})

	require.Greater(t, len(out), len(captured), "expected enriched slice longer than input")

	var sawStatic bool
	for i, r := range out {
		if i < len(captured) {
			assert.NotEqual(t, "static:js", r.Source, "static entry inside dynamic prefix at index %d", i)
			continue
		}
		if r.Source == "static:js" {
			sawStatic = true
		}
	}
	assert.True(t, sawStatic, "expected at least one static:js entry appended after dynamic prefix")
}

// TestAnalyzeJS_Disabled_ShortCircuits verifies AnalyzeJS returns the input
// slice unchanged when AnalyzeJS is false. Migrated from the CLI test.
func TestAnalyzeJS_Disabled_ShortCircuits(t *testing.T) {
	captured := jsOnlyCapture()
	out := pipeline.AnalyzeJS(context.Background(), captured, pipeline.AugmentOptions{AnalyzeJS: false})

	require.Len(t, out, len(captured), "expected unchanged slice")
	for i := range out {
		assert.Equal(t, captured[i].URL, out[i].URL, "entry %d URL mismatch", i)
	}
}

// TestAnalyzeJS_AlreadyAnalyzed_SkipsReanalysis verifies the AnyStaticSource
// idempotency guard at the AnalyzeJS-direct level: when the input already
// carries a static:js entry, the stage must skip re-analysis and return the
// slice unchanged even with AnalyzeJS=true, keeping crawl | generate
// byte-identical to a single scan. Migrated from the CLI test.
func TestAnalyzeJS_AlreadyAnalyzed_SkipsReanalysis(t *testing.T) {
	captured := append(jsOnlyCapture(), crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://example.com/api/v1/users",
		Source: crawl.SourceStaticJS,
	})
	out := pipeline.AnalyzeJS(context.Background(), captured, pipeline.AugmentOptions{
		AnalyzeJS:    true,
		AllowPrivate: true,
	})

	require.Len(t, out, len(captured), "idempotency guard should skip re-analysis")
	staticCount := 0
	for _, r := range out {
		if crawl.IsJSStaticSource(r.Source) {
			staticCount++
		}
	}
	assert.Equal(t, 1, staticCount, "expected exactly the pre-seeded static entry; guard failed to skip re-analysis")
}

// TestAnalyzeJS_ErrorPath_WarnErrorContract pins the exact warn-sink contract
// this change builds. On JS-analysis error (pre-canceled ctx) AnalyzeJS returns
// the ORIGINAL slice; the failure warning goes to WarnError (not Status) so the
// CLI can warn-always while the SDK stays silent:
//
//   - WarnError set, Status nil (CLI quiet mode): warning IS written to WarnError.
//   - Status set, WarnError nil: nothing written to Status on error (the failure
//     warning no longer routes through the verbose Status writer).
//   - Both nil (the SDK config): NOTHING written anywhere — SDK stays quiet.
//
// Migrated and extended from the CLI runJSAnalysisStage error-path test.
func TestAnalyzeJS_ErrorPath_WarnErrorContract(t *testing.T) {
	newCanceledCtx := func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}

	t.Run("WarnErrorSet_StatusNil_WritesWarningToWarnError", func(t *testing.T) {
		var warn bytes.Buffer
		captured := jsOnlyCapture()
		out := pipeline.AnalyzeJS(newCanceledCtx(), captured, pipeline.AugmentOptions{
			AnalyzeJS:    true,
			AllowPrivate: true,
			Status:       nil,
			WarnError:    &warn,
		})

		require.Len(t, out, len(captured), "expected original slice on error")
		for i := range out {
			assert.Equal(t, captured[i].URL, out[i].URL, "entry %d URL mismatch", i)
		}
		assert.Contains(t, warn.String(), "warning: js-static analysis failed",
			"failure warning must be written to WarnError even when Status is nil")
	})

	t.Run("StatusSet_WarnErrorNil_StatusStaysQuietOnError", func(t *testing.T) {
		var status bytes.Buffer
		out := pipeline.AnalyzeJS(newCanceledCtx(), jsOnlyCapture(), pipeline.AugmentOptions{
			AnalyzeJS:    true,
			AllowPrivate: true,
			Status:       &status,
			WarnError:    nil,
		})

		require.Len(t, out, len(jsOnlyCapture()), "expected original slice on error")
		assert.NotContains(t, status.String(), "warning: js-static analysis failed",
			"failure warning must NOT route through Status; it belongs on WarnError")
	})

	t.Run("BothNil_SDKConfig_NothingWrittenOnError", func(t *testing.T) {
		// The SDK passes Status=nil and WarnError=nil. On error it must emit
		// NOTHING. This asserts no panic and the original slice is returned;
		// with both sinks nil there is nowhere for output to go.
		captured := jsOnlyCapture()
		out := pipeline.AnalyzeJS(newCanceledCtx(), captured, pipeline.AugmentOptions{
			AnalyzeJS:    true,
			AllowPrivate: true,
			Status:       nil,
			WarnError:    nil,
		})
		require.Len(t, out, len(captured), "expected original slice on error (SDK quiet config)")
	})
}

// TestAnalyzeJS_ForwardsProxy is the AC-1 proof that AugmentOptions.Proxy
// reaches jsstatic.Options.Proxy: a JS bundle referencing a same-host .js.map
// sourcemap, fetched through a recording proxy, must show proxy traffic
// (LAB-4993).
func TestAnalyzeJS_ForwardsProxy(t *testing.T) {
	mapBody := []byte(`{"version":3,"sources":["app.ts"],"sourcesContent":["export const x = 1;"]}`)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js.map" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(mapBody) //nolint:errcheck,gosec // test handler
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(origin.Close)

	proxy, hits := newRecordingProxy(t, false)

	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)

	bundleURL := origin.URL + "/app.js"
	mapURL := origin.URL + "/app.js.map"
	captured := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    bundleURL,
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        []byte(fmt.Sprintf("fetch(\"/api/x\");\n//# sourceMappingURL=%s\n", mapURL)),
			},
		},
	}

	out := pipeline.AnalyzeJS(context.Background(), captured, pipeline.AugmentOptions{
		AnalyzeJS:       true,
		FetchSourcemaps: true,
		AllowPrivate:    true,
		Proxy:           httpx.ProxyConfig{URL: proxyURL},
	})
	require.Greater(t, len(out), len(captured), "expected enriched slice with sourcemap-recovered endpoints")
	assert.NotZero(t, hits.Load(), "sourcemap fetch must route through the configured proxy")
}
