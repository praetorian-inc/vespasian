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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// TestGenerateCmd_Run_WithAnalyzeJS exercises the (*GenerateCmd).Run() path
// when AnalyzeJS=true. It writes a fixture capture.json containing one JS-bundle
// ObservedRequest with a fetch("/api/discovered") call, runs Run(), and asserts
// the generated OpenAPI YAML contains /api/discovered as a path.
func TestGenerateCmd_Run_WithAnalyzeJS(t *testing.T) {
	dir := t.TempDir()

	// Build a capture fixture with one JS bundle that has a unique endpoint.
	// Use a POST fetch so the REST classifier assigns HTTPMethodConfidence=0.7 (> 0.5 threshold).
	capture := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/app.js",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        []byte(`fetch("/api/discovered", {method:"POST", body:JSON.stringify({name:"x"})})`),
			},
		},
	}
	captureData, err := json.Marshal(capture)
	if err != nil {
		t.Fatalf("marshal capture: %v", err)
	}
	captureFile := filepath.Join(dir, "capture.json")
	if err := os.WriteFile(captureFile, captureData, 0o600); err != nil {
		t.Fatalf("write capture: %v", err)
	}

	outputFile := filepath.Join(dir, "out.yaml")

	cmd := &GenerateCmd{
		APIType:         "rest",
		Capture:         captureFile,
		Output:          outputFile,
		Confidence:      0.5,
		Probe:           false, // no probing — offline test
		Deduplicate:     true,
		AnalyzeJS:       true,
		FetchSourcemaps: false,
	}

	if runErr := cmd.Run(); runErr != nil {
		t.Fatalf("Run() failed: %v", runErr)
	}

	outData, err := os.ReadFile(outputFile) //nolint:gosec // outputFile is constructed from t.TempDir() within this test
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(outData), "/api/discovered") {
		t.Errorf("expected /api/discovered in output YAML, got:\n%s", string(outData))
	}
}

// TestGenerateCmd_AnalyzeJSFlag_Defaults verifies that --analyze-js defaults
// to true and --fetch-sourcemaps defaults to false on the generate command.
func TestGenerateCmd_AnalyzeJSFlag_Defaults(t *testing.T) {
	var cli struct {
		Generate GenerateCmd `cmd:"" name:"generate"`
	}

	p := kong.Must(&cli, kong.Name("vespasian"))
	_, err := p.Parse([]string{"generate", "rest", "capture.json"})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if !cli.Generate.AnalyzeJS {
		t.Error("expected AnalyzeJS=true by default on generate")
	}
	if cli.Generate.FetchSourcemaps {
		t.Error("expected FetchSourcemaps=false by default on generate")
	}
}
