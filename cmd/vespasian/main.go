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
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/generate"
	wsdlgen "github.com/praetorian-inc/vespasian/pkg/generate/wsdl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// CLI defines the complete command-line interface structure.
var CLI struct {
	Crawl    CrawlCmd    `cmd:"" help:"Crawl a web application to discover API endpoints"`
	Import   ImportCmd   `cmd:"" help:"Import traffic capture from external sources"`
	Generate GenerateCmd `cmd:"" help:"Generate API specifications from captured traffic"`
	Scan     ScanCmd     `cmd:"" help:"Full pipeline: crawl, classify, and generate specs"`
	Version  VersionCmd  `cmd:"" help:"Show version information"`
}

// parseHeaders converts "Key: Value" strings to a map, validating for CRLF injection.
func parseHeaders(raw []string) (map[string]string, error) {
	headers := make(map[string]string)
	for _, h := range raw {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header format (expected 'Key: Value'): %q", h)
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if name == "" {
			return nil, fmt.Errorf("header has empty name: %q", h)
		}
		if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("header contains invalid CRLF characters: %q", h)
		}
		headers[name] = value
	}
	return headers, nil
}

// doCrawl executes the common crawl pipeline: parse headers, create crawler,
// run the crawl with signal handling, and return the results. On graceful
// shutdown (SIGINT/SIGTERM) partial results are returned instead of an error.
func doCrawl(targetURL string, rawHeaders []string, opts crawl.CrawlerOptions) ([]crawl.ObservedRequest, error) {
	headers, err := parseHeaders(rawHeaders)
	if err != nil {
		return nil, fmt.Errorf("invalid header: %w", err)
	}
	opts.Headers = headers

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	crawler := crawl.NewCrawler(opts)
	requests, err := crawler.Crawl(ctx, targetURL)
	if err != nil {
		if errors.Is(err, context.Canceled) && len(requests) > 0 {
			// Graceful shutdown — return partial results.
			return requests, nil
		}
		return nil, fmt.Errorf("crawl failed: %w", err)
	}
	return requests, nil
}

// writeOutput opens the output file (or stdout if path is empty), calls fn to
// write content, and ensures the file is closed properly.
func writeOutput(path string, fn func(io.Writer) error) error {
	if path == "" {
		return fn(os.Stdout)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	writeErr := fn(f)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close output file: %w", closeErr)
	}
	return nil
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
	opts := crawl.CrawlerOptions{
		Depth:    c.Depth,
		MaxPages: c.MaxPages,
		Timeout:  c.Timeout,
		Scope:    c.Scope,
		Headless: c.Headless,
	}
	requests, err := doCrawl(c.URL, c.Header, opts)
	if err != nil {
		return err
	}
	return writeOutput(c.Output, func(w io.Writer) error {
		return crawl.WriteCapture(w, requests)
	})
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
	APIType    string  `arg:"" enum:"rest,wsdl" help:"API type to generate"`
	Capture    string  `arg:"" help:"Capture file path"`
	Output     string  `short:"o" help:"Output file path"`
	Confidence float64 `default:"0.5" help:"Minimum confidence threshold"`
	Probe      bool    `default:"true" help:"Enable endpoint probing"`
	Verbose    bool    `short:"v" help:"Enable verbose logging"`
}

// Run executes the generate command.
func (c *GenerateCmd) Run() error {
	f, err := os.Open(c.Capture)
	if err != nil {
		return fmt.Errorf("failed to open capture file: %w", err)
	}
	defer f.Close()

	requests, err := crawl.ReadCapture(f)
	if err != nil {
		return fmt.Errorf("failed to read capture: %w", err)
	}

	classifiers := []classify.APIClassifier{
		&classify.RESTClassifier{},
		&classify.WSDLClassifier{},
	}
	classified := classify.Deduplicate(classify.RunClassifiers(classifiers, requests, c.Confidence))

	var filtered []classify.ClassifiedRequest
	for _, req := range classified {
		if req.APIType == c.APIType {
			filtered = append(filtered, req)
		}
	}

	if len(filtered) == 0 {
		return fmt.Errorf("no %s endpoints found in capture", c.APIType)
	}

	if c.Probe {
		var strategies []probe.ProbeStrategy
		cfg := probe.DefaultConfig()
		switch c.APIType {
		case "wsdl":
			strategies = append(strategies, probe.NewWSDLProbe(cfg))
		case "rest":
			strategies = append(strategies, probe.NewOptionsProbe(cfg))
			strategies = append(strategies, probe.NewSchemaProbe(cfg))
		}
		if len(strategies) > 0 {
			filtered, _ = probe.RunStrategies(context.Background(), strategies, filtered)
		}
	}

	var gen generate.SpecGenerator
	switch c.APIType {
	case "wsdl":
		gen = &wsdlgen.Generator{}
	default:
		return fmt.Errorf("generator for %q not yet implemented", c.APIType)
	}

	output, err := gen.Generate(filtered)
	if err != nil {
		return fmt.Errorf("generation failed: %w", err)
	}

	return writeOutput(c.Output, func(w io.Writer) error {
		_, err := w.Write(output)
		return err
	})
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
	opts := crawl.CrawlerOptions{
		Depth:    c.Depth,
		MaxPages: c.MaxPages,
		Timeout:  c.Timeout,
		Scope:    c.Scope,
		Headless: c.Headless,
	}
	requests, err := doCrawl(c.URL, c.Header, opts)
	if err != nil {
		return err
	}

	classified := classify.Deduplicate(classify.RunClassifiers(
		[]classify.APIClassifier{
			&classify.RESTClassifier{},
			&classify.WSDLClassifier{},
		},
		requests, c.Confidence,
	))

	return writeOutput(c.Output, func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(classified)
	})
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
