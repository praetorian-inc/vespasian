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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
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
