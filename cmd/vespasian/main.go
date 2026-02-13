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

// Package main is the entry point for the vespasian CLI.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/generate/rest"
)

// CLI defines the complete command-line interface structure.
var CLI struct {
	Crawl    CrawlCmd    `cmd:"" help:"Crawl a web application to discover API endpoints"`
	Import   ImportCmd   `cmd:"" help:"Import traffic capture from external sources"`
	Generate GenerateCmd `cmd:"" help:"Generate API specifications from captured traffic"`
	Scan     ScanCmd     `cmd:"" help:"Full pipeline: crawl, classify, and generate specs"`
	Version  VersionCmd  `cmd:"" help:"Show version information"`
}

// CrawlCmd crawls a web application to capture HTTP traffic.
type CrawlCmd struct {
	URL      string        `arg:"" help:"Target URL to crawl"`
	Header   []string      `short:"H" help:"Custom headers (repeatable)"`
	Output   string        `short:"o" help:"Output file path"`
	Format   string        `default:"json" enum:"json,yaml" help:"Output format"`
	Depth    int           `default:"3" help:"Maximum crawl depth"`
	MaxPages int           `default:"100" help:"Maximum pages to crawl"`
	Timeout  time.Duration `default:"30s" help:"Request timeout"`
	Scope    string        `default:"same-origin" enum:"same-origin,same-domain" help:"Crawl scope"`
	Headless bool          `default:"true" help:"Use headless browser"`
	Verbose  bool          `short:"v" help:"Enable verbose logging"`
}

// Run executes the crawl command.
func (c *CrawlCmd) Run() error {
	fmt.Println("crawl: not implemented")
	return nil
}

// ImportCmd imports traffic capture from external sources.
type ImportCmd struct {
	Format  string `arg:"" help:"Import format (e.g., burp, har, mitmproxy)"`
	File    string `arg:"" help:"Input file path"`
	Output  string `short:"o" help:"Output file path"`
	Scope   string `optional:"" help:"Filter scope (optional: same-origin or same-domain)"`
	Verbose bool   `short:"v" help:"Enable verbose logging"`
}

// Run executes the import command.
func (c *ImportCmd) Run() error {
	fmt.Println("import: not implemented")
	return nil
}

// GenerateCmd generates API specifications from captured traffic.
type GenerateCmd struct {
	APIType    string  `arg:"" enum:"rest" help:"API type to generate"`
	Capture    string  `arg:"" help:"Capture file path"`
	Output     string  `short:"o" help:"Output file path"`
	Confidence float64 `default:"0.5" help:"Minimum confidence threshold"`
	Probe      bool    `default:"true" help:"Enable endpoint probing"`
	Verbose    bool    `short:"v" help:"Enable verbose logging"`
}

// maxCaptureSize is the maximum capture file size (100MB).
const maxCaptureSize = 100 * 1024 * 1024

// Run executes the generate command.
func (c *GenerateCmd) Run() error {
	// Open capture file
	f, err := os.Open(c.Capture)
	if err != nil {
		return fmt.Errorf("opening capture file: %w", err)
	}
	defer f.Close()

	// Guard against excessively large capture files.
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat capture file: %w", err)
	}
	if info.Size() > maxCaptureSize {
		return fmt.Errorf("capture file too large: %d bytes (max %d)", info.Size(), maxCaptureSize)
	}

	// Read captured requests
	requests, err := crawl.ReadCapture(f)
	if err != nil {
		return fmt.Errorf("reading capture file: %w", err)
	}

	// TODO: Use classify.RunClassifiers() once classifier is implemented.
	// For now, treat all captured requests as API calls.
	classified := make([]classify.ClassifiedRequest, len(requests))
	for i, req := range requests {
		classified[i] = classify.ClassifiedRequest{
			ObservedRequest: req,
			IsAPI:           true,
			Confidence:      c.Confidence,
			APIType:         c.APIType,
		}
	}

	// Infer output format from file extension
	format := "yaml"
	if c.Output != "" {
		ext := strings.ToLower(filepath.Ext(c.Output))
		if ext == ".json" {
			format = "json"
		}
	}

	// Generate spec
	gen := &rest.OpenAPIGenerator{Format: format}
	spec, err := gen.Generate(classified)
	if err != nil {
		return fmt.Errorf("generating spec: %w", err)
	}

	// Guard against empty spec (no endpoints found)
	if len(spec) == 0 {
		return fmt.Errorf("no API endpoints found in capture file")
	}

	// Write output
	if c.Output != "" {
		if err := os.WriteFile(c.Output, spec, 0600); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		if c.Verbose {
			fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes)\n", c.Output, len(spec))
		}
	} else {
		fmt.Print(string(spec))
	}

	return nil
}

// ScanCmd runs the full pipeline: crawl, classify, and generate.
type ScanCmd struct {
	URL        string        `arg:"" help:"Target URL to scan"`
	Header     []string      `short:"H" help:"Custom headers (repeatable)"`
	Output     string        `short:"o" help:"Output file path"`
	Depth      int           `default:"3" help:"Maximum crawl depth"`
	MaxPages   int           `default:"100" help:"Maximum pages to crawl"`
	Timeout    time.Duration `default:"30s" help:"Request timeout"`
	Scope      string        `default:"same-origin" enum:"same-origin,same-domain" help:"Crawl scope"`
	Headless   bool          `default:"true" help:"Use headless browser"`
	Confidence float64       `default:"0.5" help:"Minimum confidence threshold"`
	Probe      bool          `default:"true" help:"Enable endpoint probing"`
	Verbose    bool          `short:"v" help:"Enable verbose logging"`
}

// Run executes the scan command.
func (c *ScanCmd) Run() error {
	fmt.Println("scan: not implemented")
	return nil
}

// VersionCmd shows version information.
type VersionCmd struct{}

// Run executes the version command.
func (c *VersionCmd) Run() error {
	fmt.Println("vespasian version dev")
	return nil
}

func main() {
	ctx := kong.Parse(&CLI,
		kong.Name("vespasian"),
		kong.Description("API discovery tool for security assessments."),
		kong.UsageOnError(),
	)
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
