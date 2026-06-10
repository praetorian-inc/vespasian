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

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/analyze/jsstatic"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	restgen "github.com/praetorian-inc/vespasian/pkg/generate/rest"
)

// smokeFixture returns a captured request slice containing one HTML page and
// one JS bundle that exercises both fetch and axios extraction.
func smokeFixture() []crawl.ObservedRequest {
	jsSrc := `fetch("/api/users", {method: "POST", body: JSON.stringify({name: "a", email: "b"})})
axios.get("/api/items/1")`
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
				Body:        []byte(jsSrc),
			},
		},
	}
}

// runSmokePipeline runs analyze → classify → dedup → generate and returns the
// YAML spec bytes plus the classified+deduped slice.
func runSmokePipeline(t *testing.T, captured []crawl.ObservedRequest, opts jsstatic.Options) ([]byte, []classify.ClassifiedRequest) {
	t.Helper()
	res, err := jsstatic.Analyze(context.Background(), captured, opts)
	if err != nil {
		t.Fatalf("jsstatic.Analyze error: %v", err)
	}

	classifiers := pipeline.ClassifiersForType("rest")
	classified := classify.RunClassifiers(classifiers, res.Requests, 0.5)
	deduped := classify.Deduplicate(classified)

	gen := &restgen.OpenAPIGenerator{}
	spec, err := gen.Generate(deduped)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	return spec, deduped
}

// TestScanPipeline_AnalyzeJS_SmokeFixture verifies end-to-end:
// (a) synthesized static:js requests appear in output;
// (b) generated YAML contains x-vespasian-source: js-bundle.
func TestScanPipeline_AnalyzeJS_SmokeFixture(t *testing.T) {
	captured := smokeFixture()
	spec, deduped := runSmokePipeline(t, captured, jsstatic.Options{})

	// (a) at least one new Source=="static:js" entry synthesized.
	var hasStatic bool
	for _, r := range deduped {
		if r.Source == "static:js" {
			hasStatic = true
			break
		}
	}
	if !hasStatic {
		t.Error("expected at least one static:js request in deduped output")
	}

	// (b) YAML contains x-vespasian-source: js-bundle.
	specStr := string(spec)
	if !strings.Contains(specStr, "x-vespasian-source: js-bundle") {
		t.Errorf("expected x-vespasian-source: js-bundle in YAML, got:\n%s", specStr)
	}
}

// TestScanPipeline_AnalyzeJS_OffMatchesBaseAndOnDoesNot exercises the actual
// --analyze-js flag-wiring path through `runJSAnalysisStage` (the same helper
// used by ScanCmd.Run / GenerateCmd.Run / CrawlCmd.Run). It runs two distinct
// pipelines:
//   - "ON" path:  runJSAnalysisStage(enabled=true) → Analyze runs, requests grow.
//   - "OFF" path: runJSAnalysisStage(enabled=false) → no-op, requests unchanged.
//
// Assertions:
//  1. ON path produces a spec that differs from the OFF path (extra endpoints discovered).
//  2. OFF path produces a spec byte-identical to a third independent baseline run.
//
// If a future change breaks the `if !args.enabled { return requests }` guard
// in runJSAnalysisStage, the OFF spec would suddenly contain static:js
// endpoints and this test would fail — making the flag wiring tamper-evident.
func TestScanPipeline_AnalyzeJS_OffMatchesBaseAndOnDoesNot(t *testing.T) {
	captured := smokeFixture()
	classifiers := pipeline.ClassifiersForType("rest")
	gen := &restgen.OpenAPIGenerator{}

	// Baseline: classify+dedup+generate against raw captured (no Analyze invoked).
	baseClassified := classify.RunClassifiers(classifiers, captured, 0.5)
	baseDeduped := classify.Deduplicate(baseClassified)
	baseSpec, err := gen.Generate(baseDeduped)
	if err != nil {
		t.Fatalf("baseline Generate error: %v", err)
	}

	// OFF path: invoke the actual production helper with enabled=false.
	offRequests := runJSAnalysisStage(context.Background(), captured, jsAnalysisArgs{
		enabled: false,
	})
	if len(offRequests) != len(captured) {
		t.Fatalf("AnalyzeJS=false: helper must return captured unchanged; got len=%d, want %d",
			len(offRequests), len(captured))
	}
	offClassified := classify.RunClassifiers(classifiers, offRequests, 0.5)
	offDeduped := classify.Deduplicate(offClassified)
	offSpec, err := gen.Generate(offDeduped)
	if err != nil {
		t.Fatalf("OFF Generate error: %v", err)
	}
	if string(offSpec) != string(baseSpec) {
		t.Error("AnalyzeJS=false: spec must be byte-identical to baseline; runJSAnalysisStage(enabled=false) altered behavior")
	}

	// ON path: invoke the helper with enabled=true.
	onRequests := runJSAnalysisStage(context.Background(), captured, jsAnalysisArgs{
		enabled: true,
	})
	if len(onRequests) <= len(captured) {
		t.Fatalf("AnalyzeJS=true: helper must append synthesized requests; got len=%d, want >%d",
			len(onRequests), len(captured))
	}
	onClassified := classify.RunClassifiers(classifiers, onRequests, 0.5)
	onDeduped := classify.Deduplicate(onClassified)
	onSpec, err := gen.Generate(onDeduped)
	if err != nil {
		t.Fatalf("ON Generate error: %v", err)
	}

	// At least one static:js entry must survive dedup.
	var hasStaticJS bool
	for _, r := range onDeduped {
		if r.Source == "static:js" {
			hasStaticJS = true
			break
		}
	}
	if !hasStaticJS {
		t.Error("AnalyzeJS=true: expected at least one static:js endpoint in deduped output")
	}

	// ON and OFF specs MUST diverge for this fixture (the JS bundle's
	// fetch/axios endpoints are not in the dynamic captured set).
	if string(onSpec) == string(offSpec) {
		t.Error("AnalyzeJS=true and AnalyzeJS=false must produce different specs for this fixture")
	}
}
