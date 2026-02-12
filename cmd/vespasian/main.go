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
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kong"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/generate"
	"github.com/praetorian-inc/vespasian/pkg/importer"
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
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	requests, err := executeCrawl(ctx, c.URL, c.Header, crawl.CrawlerOptions{
		Depth:    c.Depth,
		MaxPages: c.MaxPages,
		Timeout:  c.Timeout,
		Scope:    c.Scope,
		Headless: c.Headless,
	}, c.Verbose)
	if err != nil {
		return err
	}

	w, cleanup, err := openOutput(c.Output)
	if err != nil {
		return err
	}
	defer cleanup()

	return crawl.WriteCapture(w, requests)
}

// ImportCmd imports traffic capture from external sources.
type ImportCmd struct {
	Format  string `arg:"" enum:"burp,har,mitmproxy" help:"Import format (burp, har, mitmproxy)"`
	File    string `arg:"" help:"Input file path"`
	Output  string `short:"o" help:"Output file path"`
	Scope   string `optional:"" help:"Filter scope (optional: same-origin or same-domain)"`
	Verbose bool   `short:"v" help:"Enable verbose logging"`
}

// Run executes the import command.
func (c *ImportCmd) Run() error {
	imp, err := importer.Get(c.Format)
	if err != nil {
		return err
	}

	f, err := os.Open(c.File)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "importing %s traffic from %s\n", imp.Name(), c.File)
	}

	requests, err := imp.Import(f)
	if err != nil {
		return fmt.Errorf("import failed: %w", err)
	}

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "imported %d requests\n", len(requests))
	}

	w, cleanup, err := openOutput(c.Output)
	if err != nil {
		return err
	}
	defer cleanup()

	return crawl.WriteCapture(w, requests)
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
	f, err := os.Open(c.Capture)
	if err != nil {
		return fmt.Errorf("open capture file: %w", err)
	}
	defer func() { _ = f.Close() }()

	requests, err := crawl.ReadCapture(f)
	if err != nil {
		return fmt.Errorf("read capture file: %w", err)
	}

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "loaded %d captured requests\n", len(requests))
	}

	spec, err := generateSpec(context.Background(), requests, c.APIType, c.Confidence, c.Probe, c.Verbose)
	if err != nil {
		return err
	}

	w, cleanup, err := openOutput(c.Output)
	if err != nil {
		return err
	}
	defer cleanup()

	_, err = w.Write(spec)
	return err
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

// Run executes the scan command (crawl + generate pipeline).
func (c *ScanCmd) Run() error {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	requests, err := executeCrawl(ctx, c.URL, c.Header, crawl.CrawlerOptions{
		Depth:    c.Depth,
		MaxPages: c.MaxPages,
		Timeout:  c.Timeout,
		Scope:    c.Scope,
		Headless: c.Headless,
	}, c.Verbose)
	if err != nil {
		return err
	}

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "generating REST spec\n")
	}

	spec, err := generateSpec(ctx, requests, "rest", c.Confidence, c.Probe, c.Verbose)
	if err != nil {
		return err
	}

	w, cleanup, err := openOutput(c.Output)
	if err != nil {
		return err
	}
	defer cleanup()

	_, err = w.Write(spec)
	return err
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

// executeCrawl validates inputs, creates a crawler, and executes the crawl.
func executeCrawl(ctx context.Context, targetURL string, rawHeaders []string, opts crawl.CrawlerOptions, verbose bool) ([]crawl.ObservedRequest, error) {
	if err := validateURL(targetURL); err != nil {
		return nil, err
	}

	headers, err := parseHeaders(rawHeaders)
	if err != nil {
		return nil, err
	}
	opts.Headers = headers

	cr := crawl.NewCrawler(opts)

	if verbose {
		fmt.Fprintf(os.Stderr, "crawling %s (depth=%d, max-pages=%d, timeout=%s)\n",
			targetURL, opts.Depth, opts.MaxPages, opts.Timeout)
	}

	requests, err := cr.Crawl(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("crawl failed: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "captured %d requests\n", len(requests))
	}

	return requests, nil
}

// generateSpec runs the classify → probe → generate pipeline.
func generateSpec(ctx context.Context, requests []crawl.ObservedRequest, apiType string, confidence float64, doProbe bool, verbose bool) ([]byte, error) {
	classifiers := classifiersForType(apiType)
	classified := classify.RunClassifiers(classifiers, requests, confidence)

	if verbose {
		fmt.Fprintf(os.Stderr, "classified %d API requests (threshold=%.2f)\n", len(classified), confidence)
	}

	if doProbe {
		strategies := []probe.ProbeStrategy{
			&probe.OptionsProbe{},
			&probe.SchemaProbe{},
		}
		enriched, err := probe.RunStrategies(ctx, strategies, classified)
		if err != nil {
			return nil, fmt.Errorf("probe failed: %w", err)
		}
		classified = enriched
	}

	gen, err := generate.Get(apiType)
	if err != nil {
		return nil, err
	}

	spec, err := gen.Generate(classified)
	if err != nil {
		return nil, fmt.Errorf("generate failed: %w", err)
	}

	return spec, nil
}

// classifiersForType returns the appropriate classifiers for the given API type.
func classifiersForType(apiType string) []classify.APIClassifier {
	switch apiType {
	case "rest":
		return []classify.APIClassifier{&classify.RESTClassifier{}}
	default:
		return nil
	}
}

// validateURL checks that the given string is a valid URL with scheme and host.
func validateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid URL %q: must include scheme and host (e.g., https://example.com)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid URL %q: scheme must be http or https", rawURL)
	}
	return nil
}

// parseHeaders parses "Key: Value" header strings into a map.
func parseHeaders(headers []string) (map[string]string, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	result := make(map[string]string, len(headers))
	for _, h := range headers {
		key, value, ok := strings.Cut(h, ":")
		if !ok {
			return nil, fmt.Errorf("invalid header %q: must be in \"Key: Value\" format", h)
		}
		result[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return result, nil
}

// openOutput returns a writer for the given path, or stdout if path is empty.
// The returned cleanup function must be called when writing is complete.
func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("create output file: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}
