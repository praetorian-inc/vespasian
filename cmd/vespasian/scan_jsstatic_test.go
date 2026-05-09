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
	"testing"

	"github.com/alecthomas/kong"
)

// TestScanCmd_AnalyzeJSFlag_Defaults verifies that --analyze-js and
// --fetch-sourcemaps default to true on the scan command and can be disabled.
func TestScanCmd_AnalyzeJSFlag_Defaults(t *testing.T) {
	var cli struct {
		Scan ScanCmd `cmd:"" name:"scan"`
	}

	// Parse with defaults (no explicit flags).
	p := kong.Must(&cli, kong.Name("vespasian"))
	_, err := p.Parse([]string{"scan", "https://x"})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if !cli.Scan.AnalyzeJS {
		t.Error("expected AnalyzeJS=true by default on scan")
	}
	if !cli.Scan.FetchSourcemaps {
		t.Error("expected FetchSourcemaps=true by default on scan")
	}

	// Parse with --analyze-js=false.
	var cli2 struct {
		Scan ScanCmd `cmd:"" name:"scan"`
	}
	p2 := kong.Must(&cli2, kong.Name("vespasian"))
	_, err = p2.Parse([]string{"scan", "https://x", "--analyze-js=false"})
	if err != nil {
		t.Fatalf("parse error with --analyze-js=false: %v", err)
	}
	if cli2.Scan.AnalyzeJS {
		t.Error("expected AnalyzeJS=false after --analyze-js=false")
	}
}
