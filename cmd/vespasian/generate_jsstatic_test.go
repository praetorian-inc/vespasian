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
