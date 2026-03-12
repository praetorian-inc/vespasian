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
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/generate"
	"github.com/praetorian-inc/vespasian/pkg/importer"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// Build-time variables injected via ldflags.
var (
	version   = "dev"
	gitCommit = "unknown"
	buildDate = "unknown"
)

// CLI defines the complete command-line interface structure.
var CLI struct {
	Crawl    CrawlCmd    `cmd:"" help:"Crawl a web application to discover API endpoints"`
	Import   ImportCmd   `cmd:"" help:"Import traffic capture from external sources"`
	Generate GenerateCmd `cmd:"" help:"Generate API specifications from captured traffic"`
	Scan     ScanCmd     `cmd:"" help:"Full pipeline: crawl, classify, and generate specs"`
	Version  VersionCmd  `cmd:"" help:"Show version information"`
}

// parseHeaders converts "Key: Value" strings to a map, validating header names
// against RFC 7230 token production and header values against CRLF injection.
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
		if !isValidHeaderName(name) {
			return nil, fmt.Errorf("header name contains invalid characters (RFC 7230): %q", h)
		}
		if strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("header value contains invalid CRLF characters: %q", h)
		}
		headers[name] = value
	}
	return headers, nil
}

// isValidHeaderName checks that name consists only of RFC 7230 token characters.
// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//
//	"^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
func isValidHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return false
		}
	}
	return true
}

// isTokenChar returns true if c is a valid RFC 7230 tchar.
func isTokenChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
		c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
		c == '^' || c == '_' || c == '`' || c == '|' || c == '~':
		return true
	default:
		return false
	}
}

// shutdownBackstop is the maximum time doCrawl waits for Crawl() to return
// after context cancellation. Crawl() has internal bounded shutdown (~2.5s),
// so this is a defense-in-depth timeout that avoids blocking indefinitely if
// the engine is stuck. The force-exit handler (second signal) is the final
// safety net beyond this.
const shutdownBackstop = 10 * time.Second

// doCrawl executes the common crawl pipeline: create crawler, run the crawl
// with the provided context, and return the results. On graceful shutdown
// (SIGINT/SIGTERM) partial results are returned instead of an error.
// The stderr parameter controls where user-facing status messages are written,
// allowing tests to capture output.
//
// Goroutine lifecycle: if the backstop timer fires before Crawl() returns, the
// crawl goroutine leaks until Crawl() eventually completes. In CLI usage the
// process exits shortly after and the force-exit handler (second SIGINT) is the
// final safety net. Library callers should be aware that a stuck engine may
// leave a goroutine alive after doCrawl returns.
func doCrawl(ctx context.Context, stderr io.Writer, targetURL string, opts crawl.CrawlerOptions) ([]crawl.ObservedRequest, error) {
	opts.Stderr = stderr

	crawler := crawl.NewCrawler(opts)

	// Run Crawl in a goroutine so we can apply a backstop timeout after
	// context cancellation. Without this, a stuck Crawl() blocks forever.
	//
	// Goroutine lifecycle: if the backstop fires before Crawl() returns,
	// the goroutine remains alive until Crawl() eventually completes.
	// The buffered channel (capacity 1) ensures it won't block on send.
	// In a CLI context the process exits shortly after, and the force-exit
	// handler (second SIGINT) is the final safety net.
	type crawlResult struct {
		requests []crawl.ObservedRequest
		err      error
	}
	ch := make(chan crawlResult, 1)
	go func() {
		reqs, crawlErr := crawler.Crawl(ctx, targetURL)
		ch <- crawlResult{reqs, crawlErr}
	}()

	var requests []crawl.ObservedRequest
	var err error
	select {
	case r := <-ch:
		requests, err = r.requests, r.err
	case <-ctx.Done():
		// Context cancelled (signal or deadline). Give Crawl() up to
		// shutdownBackstop to finish its bounded internal shutdown.
		backstop := time.NewTimer(shutdownBackstop)
		select {
		case r := <-ch:
			requests, err = r.requests, r.err
		case <-backstop.C:
			return nil, fmt.Errorf("crawl failed: shutdown timed out after %s", shutdownBackstop)
		}
		backstop.Stop()
	}

	if err != nil {
		if (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) && len(requests) > 0 {
			fmt.Fprintf(stderr, "returning %d partial results\n", len(requests))
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

// CrawlOptions holds the shared crawl configuration fields used by CrawlCmd and ScanCmd.
type CrawlOptions struct {
	Header   []string      `short:"H" help:"Custom headers (repeatable)"`
	Output   string        `short:"o" help:"Output file path"`
	Depth    int           `default:"3" help:"Maximum crawl depth"`
	MaxPages int           `default:"100" help:"Maximum pages to crawl"`
	Timeout  time.Duration `default:"10m" help:"Maximum duration for the entire crawl"`
	Scope    string        `default:"same-origin" enum:"same-origin,same-domain" help:"Crawl scope"`
	Headless bool          `default:"true" help:"Use headless browser"`
	Verbose  bool          `short:"v" help:"Enable verbose logging"`
}

// setupForceExitHandler spawns a goroutine that waits for the first signal
// to be handled (ctx.Done), then registers for a second SIGINT/SIGTERM and
// force-exits the process. This avoids a race where both the graceful handler
// and the force-exit handler consume the same signal simultaneously.
//
// The cleanup function is called before exiting to perform best-effort resource
// cleanup (e.g., removing temp directories) that would otherwise be skipped by
// os.Exit bypassing deferred functions. Chrome is already dead at this point
// (killed on first signal), so cleanup is purely disk hygiene.
func setupForceExitHandler(ctx context.Context, stderr io.Writer, cleanup func(), exitFn func(int)) {
	go func() {
		<-ctx.Done() // First signal consumed by signal.NotifyContext
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		onForceExit(stderr, cleanup, exitFn)
	}()
}

// onForceExit is the testable core of setupForceExitHandler. It runs cleanup
// (with panic recovery to guarantee exitFn is called), writes the exit message,
// and calls exitFn. Extracted so tests can exercise the logic without sending
// real signals.
func onForceExit(stderr io.Writer, cleanup func(), exitFn func(int)) {
	if cleanup != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(stderr, "cleanup panicked: %v\n", r)
				}
			}()
			cleanup()
		}()
	}
	fmt.Fprintf(stderr, "forcing immediate exit\n")
	exitFn(1)
}

// browserSetupResult holds the resources created by setupBrowserAndSignals.
type browserSetupResult struct {
	opts    crawl.CrawlerOptions
	ctx     context.Context
	cleanup func() // caller must defer this
}

// setupBrowserAndSignals validates headers, creates a BrowserManager (if
// headless), wires up signal handling with force-exit support, and returns a
// cancellable context. Headers are validated before launching Chrome so that
// invalid headers fail fast without wasting browser startup time. The returned
// cleanup function closes the browser and stops the signal handler; callers
// must defer it.
func setupBrowserAndSignals(rawHeaders []string, crawlOpts CrawlOptions, extraOpts crawl.CrawlerOptions) (browserSetupResult, error) {
	// Validate headers before launching Chrome — fail fast on invalid input.
	headers, err := parseHeaders(rawHeaders)
	if err != nil {
		return browserSetupResult{}, fmt.Errorf("invalid header: %w", err)
	}
	extraOpts.Headers = headers

	var browserMgr *crawl.BrowserManager

	if crawlOpts.Headless {
		browserMgr, err = crawl.NewBrowserManager(crawl.BrowserOptions{Headless: true})
		if err != nil {
			return browserSetupResult{}, fmt.Errorf("launch browser: %w", err)
		}
		extraOpts.BrowserMgr = browserMgr
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	// Single closure for browser teardown, shared between the force-exit
	// handler and the deferred cleanup. BrowserManager.Close() is already
	// idempotent (sync.Once), but a shared closure makes the intent explicit
	// and avoids duplicating the nil-check.
	closeBrowser := func() {
		if browserMgr != nil {
			browserMgr.Close()
		}
	}

	setupForceExitHandler(ctx, os.Stderr, closeBrowser, os.Exit)

	cleanup := func() {
		stop()
		closeBrowser()
	}

	return browserSetupResult{
		opts:    extraOpts,
		ctx:     ctx,
		cleanup: cleanup,
	}, nil
}

// CrawlCmd crawls a web application to capture HTTP traffic.
type CrawlCmd struct {
	URL    string `arg:"" help:"Target URL to crawl"`
	Format string `default:"json" enum:"json,yaml" help:"Output format"`
	CrawlOptions
}

// Run executes the crawl command.
func (c *CrawlCmd) Run() error {
	if err := validateURL(c.URL); err != nil {
		return err
	}

	bs, err := setupBrowserAndSignals(c.Header, c.CrawlOptions, crawl.CrawlerOptions{
		Depth:    c.Depth,
		MaxPages: c.MaxPages,
		Timeout:  c.Timeout,
		Scope:    c.Scope,
		Headless: c.Headless,
	})
	if err != nil {
		return err
	}
	defer bs.cleanup()

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "crawling %s (depth=%d, max-pages=%d, timeout=%s)\n",
			c.URL, bs.opts.Depth, bs.opts.MaxPages, bs.opts.Timeout)
	}

	requests, err := doCrawl(bs.ctx, os.Stderr, c.URL, bs.opts)
	if err != nil {
		return err
	}

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "captured %d requests\n", len(requests))
	}

	return writeOutput(c.Output, func(w io.Writer) error {
		return crawl.WriteCapture(w, requests)
	})
}

// ImportCmd imports traffic capture from external sources.
type ImportCmd struct {
	Format  string `arg:"" enum:"burp,har,mitmproxy" help:"Import format (burp, har, mitmproxy)"`
	File    string `arg:"" help:"Input file path"`
	Output  string `short:"o" help:"Output file path"`
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

	return writeOutput(c.Output, func(w io.Writer) error {
		return crawl.WriteCapture(w, requests)
	})
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

// maxCaptureSize is the maximum capture file size (100MB).
const maxCaptureSize = 100 * 1024 * 1024

// Run executes the generate command.
func (c *GenerateCmd) Run() (err error) {
	f, err := os.Open(c.Capture)
	if err != nil {
		return fmt.Errorf("open capture file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing capture file: %w", cerr)
		}
	}()

	// Guard against excessively large capture files.
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat capture file: %w", err)
	}
	if info.Size() > maxCaptureSize {
		return fmt.Errorf("capture file too large: %d bytes (max %d)", info.Size(), maxCaptureSize)
	}

	requests, err := crawl.ReadCapture(f)
	if err != nil {
		return fmt.Errorf("read capture file: %w", err)
	}

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "loaded %d captured requests\n", len(requests))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := generateSpec(ctx, requests, c.APIType, c.Confidence, c.Probe, c.Verbose)
	if err != nil {
		return err
	}

	return writeOutput(c.Output, func(w io.Writer) error {
		_, writeErr := w.Write(spec)
		return writeErr
	})
}

// ScanCmd runs the full pipeline: crawl, classify, and generate.
type ScanCmd struct {
	URL        string  `arg:"" help:"Target URL to scan"`
	Confidence float64 `default:"0.5" help:"Minimum confidence threshold"`
	Probe      bool    `default:"true" help:"Enable endpoint probing"`
	CrawlOptions
}

// Run executes the scan command (crawl + generate pipeline).
func (c *ScanCmd) Run() error {
	if err := validateURL(c.URL); err != nil {
		return err
	}

	bs, err := setupBrowserAndSignals(c.Header, c.CrawlOptions, crawl.CrawlerOptions{
		Depth:    c.Depth,
		MaxPages: c.MaxPages,
		Timeout:  c.Timeout,
		Scope:    c.Scope,
		Headless: c.Headless,
	})
	if err != nil {
		return err
	}
	defer bs.cleanup()

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "crawling %s (depth=%d, max-pages=%d, timeout=%s)\n",
			c.URL, bs.opts.Depth, bs.opts.MaxPages, bs.opts.Timeout)
	}

	requests, err := doCrawl(bs.ctx, os.Stderr, c.URL, bs.opts)
	if err != nil {
		return err
	}

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "captured %d requests\n", len(requests))
		fmt.Fprintf(os.Stderr, "generating REST spec\n")
	}

	spec, err := generateSpec(bs.ctx, requests, "rest", c.Confidence, c.Probe, c.Verbose)
	if err != nil {
		return err
	}

	return writeOutput(c.Output, func(w io.Writer) error {
		_, writeErr := w.Write(spec)
		return writeErr
	})
}

// VersionCmd shows version information.
type VersionCmd struct{}

// Run executes the version command.
func (c *VersionCmd) Run() error {
	fmt.Printf("vespasian %s (commit: %s, built: %s)\n", version, gitCommit, buildDate)
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

// generateSpec runs the classify → probe → generate pipeline.
func generateSpec(ctx context.Context, requests []crawl.ObservedRequest, apiType string, confidence float64, doProbe bool, verbose bool) ([]byte, error) {
	classifiers := classifiersForType(apiType)
	if classifiers == nil {
		return nil, fmt.Errorf("unsupported API type: %q", apiType)
	}
	classified := classify.Deduplicate(classify.RunClassifiers(classifiers, requests, confidence))

	if verbose {
		fmt.Fprintf(os.Stderr, "classified %d API requests (threshold=%.2f)\n", len(classified), confidence)
	}

	if doProbe {
		var strategies []probe.ProbeStrategy
		switch apiType {
		case "wsdl":
			strategies = []probe.ProbeStrategy{probe.NewWSDLProbe(probe.DefaultConfig())}
		default:
			strategies = []probe.ProbeStrategy{
				&probe.OptionsProbe{},
				&probe.SchemaProbe{},
			}
		}
		enriched, probeErrs := probe.RunStrategies(ctx, strategies, classified)
		if verbose {
			for _, e := range probeErrs {
				fmt.Fprintf(os.Stderr, "probe warning: %v\n", e)
			}
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
	case "wsdl":
		return []classify.APIClassifier{&classify.WSDLClassifier{}}
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
