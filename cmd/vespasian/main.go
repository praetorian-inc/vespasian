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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	wsdlgen "github.com/praetorian-inc/vespasian/pkg/generate/wsdl"
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
	NoBanner bool        `help:"Suppress the startup banner" name:"no-banner"`
	Crawl    CrawlCmd    `cmd:"" help:"Crawl a web application to discover API endpoints"`
	Import   ImportCmd   `cmd:"" help:"Import traffic capture from external sources"`
	Generate GenerateCmd `cmd:"" help:"Generate API specifications from captured traffic"`
	Scan     ScanCmd     `cmd:"" help:"Full pipeline: crawl, classify, and generate specs"`
	Version  VersionCmd  `cmd:"" help:"Show version information"`
}

// RequestIDHeader is the header name used for crawl session traceability.
const RequestIDHeader = "X-Vespasian-Request-Id"

// generateRequestID produces a 32-character hex string from 16 random bytes.
func generateRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// headerExistsCaseInsensitive checks whether a header name exists in the map
// using a case-insensitive comparison, per RFC 7230.
func headerExistsCaseInsensitive(headers map[string]string, name string) bool {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// injectRequestID adds an auto-generated X-Vespasian-Request-Id header to the
// map unless disabled or the user already supplied one via -H. Returns the
// generated ID (empty if skipped or user-supplied).
func injectRequestID(headers map[string]string, disabled bool) (string, error) {
	if disabled {
		return "", nil
	}
	if headerExistsCaseInsensitive(headers, RequestIDHeader) {
		return "", nil
	}
	id, err := generateRequestID()
	if err != nil {
		return "", err
	}
	headers[RequestIDHeader] = id
	return id, nil
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
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("header value contains invalid characters: %q", h)
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
func isTokenChar(c byte) bool { //nolint:gocyclo // character-class lookup table
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

	if opts.Proxy != "" && !opts.Headless {
		fmt.Fprintf(stderr, "warning: --proxy is only supported with headless browser mode; ignoring proxy setting\n") //nolint:errcheck // best-effort warning
		opts.Proxy = ""
	}

	// Safety: opts.Proxy is printed below. All current callers (CrawlCmd.Run,
	// ScanCmd.Run) validate via setupBrowserAndSignals → validateProxyAddr first,
	// which rejects embedded credentials. If adding a new caller, ensure
	// validateProxyAddr runs before reaching this point.
	if opts.Proxy != "" {
		if u, err := url.Parse(opts.Proxy); err == nil && u.Port() == "" {
			fmt.Fprintf(stderr, "warning: --proxy address %q has no explicit port; most proxies require one (e.g., :8080)\n", opts.Proxy) //nolint:errcheck // best-effort warning
		}
	}

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
		// Context canceled (signal or deadline). Give Crawl() up to
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
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if len(requests) > 0 {
				noun := "results"
				if len(requests) == 1 {
					noun = "result"
				}
				fmt.Fprintf(stderr, "returning %d partial %s\n", len(requests), noun) //nolint:errcheck // best-effort status message
			}
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) //nolint:gosec // G304: CLI tool, user controls output path
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
	Header      []string      `short:"H" help:"Custom headers (repeatable)"`
	Output      string        `short:"o" help:"Output file path"`
	Depth       int           `default:"3" help:"Maximum crawl depth"`
	MaxPages    int           `default:"100" help:"Maximum pages to crawl"`
	Timeout     time.Duration `default:"10m" help:"Maximum duration for the entire crawl"`
	Scope       string        `default:"same-origin" enum:"same-origin,same-domain" help:"Crawl scope"`
	Headless    bool          `default:"true" help:"Use headless browser"`
	Proxy       string        `help:"Proxy address for headless browser (e.g., http://127.0.0.1:8080). Note: TLS certificate verification is disabled during crawls."`
	NoRequestID bool          `name:"no-request-id" help:"Disable automatic X-Vespasian-Request-Id header"`
	Verbose     bool          `short:"v" help:"Enable verbose logging"`
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
					fmt.Fprintf(stderr, "cleanup panicked: %v\n", r) //nolint:errcheck // best-effort panic message
				}
			}()
			cleanup()
		}()
	}
	fmt.Fprintf(stderr, "forcing immediate exit\n") //nolint:errcheck // best-effort status message
	exitFn(1)
}

// browserSetupResult holds the resources created by setupBrowserAndSignals.
type browserSetupResult struct {
	opts      crawl.CrawlerOptions
	ctx       context.Context
	cleanup   func() // caller must defer this
	requestID string // auto-generated session ID; empty if disabled or user-supplied
}

// setupBrowserAndSignals validates headers, injects the request ID header (if
// enabled), creates a BrowserManager (if headless), wires up signal handling
// with force-exit support, and returns a cancellable context. Headers are
// validated before launching Chrome so that invalid headers fail fast without
// wasting browser startup time. The returned cleanup function closes the
// browser and stops the signal handler; callers must defer it.
func setupBrowserAndSignals(rawHeaders []string, crawlOpts CrawlOptions, extraOpts crawl.CrawlerOptions) (browserSetupResult, error) {
	// Validate headers before launching Chrome — fail fast on invalid input.
	headers, err := parseHeaders(rawHeaders)
	if err != nil {
		return browserSetupResult{}, fmt.Errorf("invalid header: %w", err)
	}

	requestID, err := injectRequestID(headers, crawlOpts.NoRequestID)
	if err != nil {
		return browserSetupResult{}, err
	}

	extraOpts.Headers = headers

	var browserMgr *crawl.BrowserManager

	if crawlOpts.Headless {
		browserMgr, err = crawl.NewBrowserManager(crawl.BrowserOptions{Headless: true, Proxy: crawlOpts.Proxy})
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
		opts:      extraOpts,
		ctx:       ctx,
		cleanup:   cleanup,
		requestID: requestID,
	}, nil
}

// CrawlCmd crawls a web application to capture HTTP traffic.
type CrawlCmd struct {
	URL string `arg:"" help:"Target URL to crawl"`
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
		Proxy:    c.Proxy,
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
		if bs.requestID != "" {
			fmt.Fprintf(os.Stderr, "request-id: %s\n", bs.requestID)
		}
		fmt.Fprintf(os.Stderr, "captured %d requests\n", len(requests)) //nolint:gosec // G705: writing to stderr, not web response
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
	defer f.Close() //nolint:errcheck // read-only file

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "importing %s traffic from %s\n", imp.Name(), c.File)
	}

	requests, err := imp.Import(f)
	if err != nil {
		return fmt.Errorf("import failed: %w", err)
	}

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "imported %d requests\n", len(requests)) //nolint:gosec // G705: writing to stderr, not web response
	}

	return writeOutput(c.Output, func(w io.Writer) error {
		return crawl.WriteCapture(w, requests)
	})
}

// GenerateCmd generates API specifications from captured traffic.
type GenerateCmd struct {
	APIType               string  `arg:"" enum:"rest,wsdl,graphql" help:"API type to generate (rest, wsdl, graphql)"`
	Capture               string  `arg:"" help:"Capture file path"`
	Output                string  `short:"o" help:"Output file path"`
	Confidence            float64 `default:"0.5" help:"Minimum confidence threshold"`
	Probe                 bool    `default:"true" help:"Enable endpoint probing"`
	Deduplicate           bool    `default:"true" help:"Deduplicate classified endpoints before probing"`
	DangerousAllowPrivate bool    `help:"Disable SSRF protection for crawling and probes, allowing private/localhost targets. Required when the seed URL is a private host. WARNING: Do not use on production systems." name:"dangerous-allow-private"`
	Verbose               bool    `short:"v" help:"Enable verbose logging"`
}

// API type constants used for classification routing and generation.
const (
	apiTypeAuto    = "auto"
	apiTypeREST    = "rest"
	apiTypeWSDL    = "wsdl"
	apiTypeGraphQL = "graphql"
)

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
		fmt.Fprintf(os.Stderr, "loaded %d captured requests\n", len(requests)) //nolint:gosec // G705: writing to stderr, not web response
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := generateSpec(ctx, requests, generateSpecOptions{
		APIType:      c.APIType,
		Confidence:   c.Confidence,
		Probe:        c.Probe,
		Deduplicate:  c.Deduplicate,
		AllowPrivate: c.DangerousAllowPrivate,
		Verbose:      c.Verbose,
	})
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
	URL                   string  `arg:"" help:"Target URL to scan"`
	APIType               string  `default:"auto" enum:"auto,rest,wsdl,graphql" help:"API type to generate (auto detects from traffic)" name:"api-type"`
	Confidence            float64 `default:"0.5" help:"Minimum confidence threshold"`
	Probe                 bool    `default:"true" help:"Enable endpoint probing"`
	Deduplicate           bool    `default:"true" help:"Deduplicate classified endpoints before probing"`
	DangerousAllowPrivate bool    `help:"Disable SSRF protection for crawling and probes, allowing private/localhost targets. Required when the seed URL is a private host. WARNING: Do not use on production systems." name:"dangerous-allow-private"`

	CrawlOptions
}

// Run executes the scan command (crawl + generate pipeline).
func (c *ScanCmd) Run() error { //nolint:gocyclo // top-level orchestration
	if err := validateURL(c.URL); err != nil {
		return err
	}

	bs, err := setupBrowserAndSignals(c.Header, c.CrawlOptions, crawl.CrawlerOptions{
		Depth:    c.Depth,
		MaxPages: c.MaxPages,
		Timeout:  c.Timeout,
		Scope:    c.Scope,
		Headless: c.Headless,
		Proxy:    c.Proxy,
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
		if bs.requestID != "" {
			fmt.Fprintf(os.Stderr, "request-id: %s\n", bs.requestID)
		}
		fmt.Fprintf(os.Stderr, "captured %d requests\n", len(requests)) //nolint:gosec // G705: writing to stderr, not web response
	}

	apiType := c.APIType
	if apiType == apiTypeAuto {
		apiType = detectAPIType(requests, c.Confidence)
		if c.Verbose {
			fmt.Fprintf(os.Stderr, "detected API type: %s\n", apiType) //nolint:gosec // G705: writing to stderr, not web response
		}
	}

	// When auto-detection or explicit WSDL mode is active, try fetching a
	// WSDL document from <targetURL>?wsdl. SOAP services return HTML for
	// browser GETs so crawl traffic rarely contains WSDL signals — active
	// probing is the reliable discovery method.
	if apiType == apiTypeAuto || apiType == apiTypeWSDL || apiType == apiTypeREST {
		wsdlDoc := probeWSDLDocument(c.URL, c.DangerousAllowPrivate, c.Verbose)
		if wsdlDoc != nil {
			apiType = apiTypeWSDL
			if c.Verbose {
				fmt.Fprintf(os.Stderr, "discovered WSDL document at %s?wsdl\n", c.URL)
			}
			// Inject a synthetic request carrying the WSDL document so
			// the generator's Phase 1 can return it directly.
			requests = append(requests, crawl.ObservedRequest{
				Method: "GET",
				URL:    c.URL + "?wsdl",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/xml",
					Body:        wsdlDoc,
				},
			})
		}
	}

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "generating %s spec\n", apiTypeDisplayName(apiType)) //nolint:gosec // G705: writing to stderr, not web response
	}

	// Create a fresh signal context for the generate phase. If a signal
	// interrupted the crawl, bs.ctx is already canceled — doCrawl swallowed
	// the error and returned partial results. Using the canceled context
	// would cause generateSpec's probing to bail out immediately.
	genCtx, genStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer genStop()

	// Replay JS-extracted URLs with raw HTTP to bypass SPA catch-all routing.
	// URLs extracted from JavaScript bundles are visited by the headless browser,
	// which gets the SPA shell (index.html) instead of the API response. Re-fetching
	// them with a direct HTTP request reaches the actual API backend.
	requests = crawl.ReplayJSExtracted(genCtx, requests, crawl.JSReplayConfig{
		Headers:      bs.opts.Headers,
		TargetURL:    c.URL,
		AllowPrivate: c.DangerousAllowPrivate,
		Verbose:      c.Verbose,
		Stderr:       os.Stderr,
	})

	spec, err := generateSpec(genCtx, requests, generateSpecOptions{
		APIType:      apiType,
		Confidence:   c.Confidence,
		Probe:        c.Probe,
		Deduplicate:  c.Deduplicate,
		AllowPrivate: c.DangerousAllowPrivate,
		Verbose:      c.Verbose,
	})
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
	if !CLI.NoBanner {
		printBanner()
	}
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

// generateSpecOptions holds parameters for generateSpec, avoiding consecutive
// bool arguments that are easy to transpose at call sites.
type generateSpecOptions struct {
	APIType      string
	Confidence   float64
	Probe        bool
	Deduplicate  bool
	AllowPrivate bool
	Verbose      bool
}

// generateSpec runs the classify → probe → generate pipeline.
func generateSpec(ctx context.Context, requests []crawl.ObservedRequest, opts generateSpecOptions) ([]byte, error) {
	classifiers := classifiersForType(opts.APIType)
	if classifiers == nil {
		return nil, fmt.Errorf("unsupported API type: %q", opts.APIType)
	}
	classified := classify.RunClassifiers(classifiers, requests, opts.Confidence)
	if opts.Deduplicate {
		classified = classify.Deduplicate(classified)
	}

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "classified %d API requests (threshold=%.2f)\n", len(classified), opts.Confidence) //nolint:gosec // G705: writing to stderr, not web response
	}

	if opts.AllowPrivate && opts.Probe {
		fmt.Fprintf(os.Stderr, "WARNING: SSRF protection disabled — probes may target private/internal networks\n")
	}

	if opts.Probe {
		cfg := probe.DefaultConfig()
		if opts.AllowPrivate {
			cfg.URLValidator = func(string) error { return nil }
			cfg.Client = &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Transport: &http.Transport{
					TLSHandshakeTimeout:   10 * time.Second,
					ResponseHeaderTimeout: 10 * time.Second,
				},
			}
		}
		var strategies []probe.ProbeStrategy
		switch opts.APIType {
		case apiTypeWSDL:
			strategies = []probe.ProbeStrategy{probe.NewWSDLProbe(cfg)}
		case apiTypeGraphQL:
			strategies = []probe.ProbeStrategy{probe.NewGraphQLProbe(cfg)}
		default:
			strategies = []probe.ProbeStrategy{
				probe.NewOptionsProbe(cfg),
				probe.NewSchemaProbe(cfg),
			}
		}
		enriched, probeErrs := probe.RunStrategies(ctx, strategies, classified)
		if opts.Verbose {
			for _, e := range probeErrs {
				fmt.Fprintf(os.Stderr, "probe warning: %v\n", e)
			}
		}
		classified = enriched
	}

	gen, err := generate.Get(opts.APIType)
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
	case apiTypeREST:
		return []classify.APIClassifier{&classify.RESTClassifier{}}
	case apiTypeWSDL:
		return []classify.APIClassifier{&classify.WSDLClassifier{}}
	case apiTypeGraphQL:
		return []classify.APIClassifier{&classify.GraphQLClassifier{}}
	default:
		return nil
	}
}

// detectAPIType runs both WSDL and REST classifiers against captured traffic
// and returns the API type with the most matches. For WSDL to win, it must
// have at least one match AND represent the majority of classified traffic.
// When WSDL matches exist but are the minority (mixed REST+SOAP), REST is
// returned to avoid losing REST endpoint discovery.
//
// Note: this performs a lightweight classification pass separate from the full
// RunClassifiers call inside generateSpec. The duplication is intentional —
// detectAPIType only needs to answer "which generator?", while generateSpec's
// pass produces the full ClassifiedRequest slice needed for generation.
func detectAPIType(requests []crawl.ObservedRequest, threshold float64) string {
	wsdlClassifier := &classify.WSDLClassifier{}
	restClassifier := &classify.RESTClassifier{}
	graphqlClassifier := &classify.GraphQLClassifier{}

	var wsdlCount, restCount, graphqlCount int
	for _, req := range requests {
		if isAPI, confidence := wsdlClassifier.Classify(req); isAPI && confidence >= threshold {
			wsdlCount++
		}
		if isAPI, confidence := restClassifier.Classify(req); isAPI && confidence >= threshold {
			restCount++
		}
		if isAPI, confidence := graphqlClassifier.Classify(req); isAPI && confidence >= threshold {
			graphqlCount++
		}
	}

	// GraphQL wins when it has matches and at least as many as both others.
	if graphqlCount > 0 && graphqlCount >= wsdlCount && graphqlCount >= restCount {
		return apiTypeGraphQL
	}
	// WSDL wins only when it has matches and they represent the majority
	// of classified traffic (or there are no REST matches at all).
	if wsdlCount > 0 && wsdlCount >= restCount {
		return apiTypeWSDL
	}
	return apiTypeREST
}

// probeWSDLDocument attempts to fetch a WSDL document from targetURL?wsdl.
// Returns the raw WSDL bytes if the response is a valid WSDL document, or nil
// if the probe fails or returns non-WSDL content. This is the primary WSDL
// discovery mechanism for the scan pipeline because headless browser crawls
// of SOAP endpoints typically capture HTML, not XML.
func probeWSDLDocument(targetURL string, allowPrivate bool, verbose bool) []byte {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "wsdl discovery: invalid URL %q: %v\n", targetURL, err) //nolint:errcheck,gosec // best-effort status message
		}
		return nil
	}
	parsedURL.RawQuery = "wsdl"
	wsdlURL := parsedURL.String()

	if verbose {
		fmt.Fprintf(os.Stderr, "wsdl discovery: probing %s\n", wsdlURL)
	}

	if !allowPrivate {
		if err := probe.ValidateProbeURL(wsdlURL); err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "wsdl discovery: skipping %s (SSRF protection: %v)\n", wsdlURL, err)
			}
			return nil
		}
	}

	transport := &http.Transport{
		DialContext: probe.SSRFSafeDialContext,
	}
	if allowPrivate {
		transport = &http.Transport{}
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(wsdlURL)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "wsdl discovery: request failed: %v\n", err)
		}
		return nil
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck,gosec // best-effort drain
		resp.Body.Close()                                    //nolint:errcheck,gosec // best-effort close
	}()

	if resp.StatusCode >= 400 {
		if verbose {
			fmt.Fprintf(os.Stderr, "wsdl discovery: %s returned HTTP %d\n", wsdlURL, resp.StatusCode)
		}
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB limit
	if err != nil {
		return nil
	}

	// Validate the response is actually a WSDL document
	if _, parseErr := wsdlgen.ParseWSDL(body); parseErr != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "wsdl discovery: response is not valid WSDL: %v\n", parseErr)
		}
		return nil
	}

	return body
}

// apiTypeDisplayName returns a human-readable display name for an API type.
func apiTypeDisplayName(apiType string) string {
	switch apiType {
	case apiTypeREST:
		return "REST"
	case apiTypeWSDL:
		return "WSDL"
	case apiTypeGraphQL:
		return "GraphQL"
	default:
		return apiType
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
