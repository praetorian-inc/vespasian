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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
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
	// Parse headers from "Key: Value" format
	headers := make(map[string]string)
	for _, h := range c.Header {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Create crawler options
	opts := crawl.CrawlerOptions{
		Depth:    c.Depth,
		MaxPages: c.MaxPages,
		Timeout:  c.Timeout,
		Scope:    c.Scope,
		Headless: c.Headless,
		Headers:  headers,
	}

	// Create context with signal handling for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Create crawler and execute
	crawler := crawl.NewCrawler(opts)
	requests, err := crawler.Crawl(ctx, c.URL)
	if err != nil {
		return fmt.Errorf("crawl failed: %w", err)
	}

	// Determine output writer
	var writer *os.File
	if c.Output != "" {
		writer, err = os.Create(c.Output)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer writer.Close()
	} else {
		writer = os.Stdout
	}

	// Write results
	if err := crawl.WriteCapture(writer, requests); err != nil {
		return fmt.Errorf("failed to write capture: %w", err)
	}

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

// Run executes the generate command.
func (c *GenerateCmd) Run() error {
	fmt.Println("generate: not implemented")
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
	// Parse headers from "Key: Value" format
	headers := make(map[string]string)
	for _, h := range c.Header {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Create crawler options
	opts := crawl.CrawlerOptions{
		Depth:    c.Depth,
		MaxPages: c.MaxPages,
		Timeout:  c.Timeout,
		Scope:    c.Scope,
		Headless: c.Headless,
		Headers:  headers,
	}

	// Create context with signal handling for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Create crawler and execute
	crawler := crawl.NewCrawler(opts)
	requests, err := crawler.Crawl(ctx, c.URL)
	if err != nil {
		return fmt.Errorf("crawl failed: %w", err)
	}

	// Classify API requests
	classifiers := []classify.APIClassifier{&classify.RESTClassifier{}}
	classified := classify.RunClassifiers(classifiers, requests, c.Confidence)

	// Determine output writer
	var writer *os.File
	if c.Output != "" {
		writer, err = os.Create(c.Output)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer writer.Close()
	} else {
		writer = os.Stdout
	}

	// Write classified results as JSON
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(classified); err != nil {
		return fmt.Errorf("failed to write classified results: %w", err)
	}

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
