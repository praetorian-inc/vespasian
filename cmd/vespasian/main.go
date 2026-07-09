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
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/importer"
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

// parseHeaders converts "Key: Value" strings to a map. Validation is delegated
// to crawl.ParseHeader (RFC 7230 names; no CR/LF/NUL in values).
func parseHeaders(raw []string) (map[string]string, error) {
	headers := make(map[string]string)
	for _, h := range raw {
		name, value, err := crawl.ParseHeader(h)
		if err != nil {
			return nil, err
		}
		headers[name] = value
	}
	return headers, nil
}

// warnSSRFDisabled writes the SSRF-protection warning to stderr when both
// allowPrivate and probe are enabled. The combination means active probes may
// reach private/internal hosts.
func warnSSRFDisabled(allowPrivate, probe bool) {
	if allowPrivate && probe {
		fmt.Fprintf(os.Stderr, "WARNING: SSRF protection disabled — probes may target private/internal networks\n") //nolint:errcheck // best-effort warning
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

	// --proxy is honored on both backends: the headless path routes Chrome via
	// --proxy-server, the HTTP path routes the net/http transport (LAB-4011).
	// Validate here BEFORE opts.Proxy is printed below so an invalid or
	// credential-bearing address is rejected (and never logged). The backends
	// re-validate (NewBrowserManager for headless, HTTPCrawler.Crawl for HTTP),
	// so library/SDK callers are covered independently of this CLI check.
	if opts.Proxy != "" {
		if err := crawl.ValidateProxyAddr(opts.Proxy); err != nil {
			return nil, err
		}
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
	Header          []string      `short:"H" help:"Custom headers (repeatable)"`
	Output          string        `short:"o" help:"Output file path"`
	Depth           int           `default:"3" help:"Maximum crawl depth"`
	MaxPages        int           `default:"100" help:"Maximum pages to crawl"`
	Timeout         time.Duration `default:"10m" help:"Maximum duration for the entire crawl"`
	Scope           string        `default:"same-origin" enum:"same-origin,same-domain" help:"Crawl scope"`
	Headless        bool          `default:"true" help:"Use headless browser"`
	Proxy           string        `help:"Proxy address for the crawl stage (e.g., http://127.0.0.1:8080); http/https/socks5. Routes crawl traffic through the proxy on both crawler backends: Chrome (headless) or the net/http transport (--headless=false). Probe and JS-replay traffic is not proxied. TLS verification stays on by default; use --proxy-insecure to accept an intercepting proxy's MITM certificate on the net/http backend. With --proxy the dial-time SSRF IP pin is skipped for the proxy connection; URL scope is still enforced, so private targets still require --dangerous-allow-private."`
	ProxyInsecure   bool          `name:"proxy-insecure" help:"Disable TLS certificate verification for an http/https intercepting proxy (Burp/mitmproxy MITM) on the net/http backend (--headless=false). Off by default; no effect on socks5 or the headless backend (there, trust the proxy CA via the OS trust store instead)."`
	Concurrency     int           `default:"10" help:"Number of concurrent browser tabs for headless crawling"`
	NoRequestID     bool          `name:"no-request-id" help:"Disable automatic X-Vespasian-Request-Id header"`
	Verbose         bool          `short:"v" help:"Enable verbose logging"`
	AnalyzeJS       bool          `name:"analyze-js"      default:"true"  help:"Statically analyze captured JS bundles to discover API endpoints, parameters, and request bodies."`
	FetchSourcemaps bool          `name:"fetch-sourcemaps" default:"true"  help:"When --analyze-js is set, fetch .js.map sourcemaps referenced via //# sourceMappingURL= comments to recover original sources."`
}

// SlugOptions holds the path-normalization flags shared by GenerateCmd and ScanCmd.
type SlugOptions struct {
	MergeSlugs    bool `name:"merge-slugs" help:"Enable slug-based path merging (off by default). See README for when to use this vs. distinct endpoint preservation."`
	SlugThreshold int  `name:"slug-threshold" default:"2" help:"Distinct values required at a path position before --merge-slugs collapses it; higher is more conservative (minimum 2). See README."`
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
	URL                   string `arg:"" help:"Target URL to crawl"`
	DangerousAllowPrivate bool   `help:"Disable SSRF protection for crawling, allowing private/localhost targets (localhost, 127.0.0.1, RFC1918, link-local). Required when the seed URL is a private host, otherwise the crawl exits with an error and captures nothing. WARNING: Do not use on production systems." name:"dangerous-allow-private"`
	CrawlOptions
}

// Run executes the crawl command.
func (c *CrawlCmd) Run() error {
	if err := validateURL(c.URL); err != nil {
		return err
	}

	bs, err := setupBrowserAndSignals(c.Header, c.CrawlOptions, crawl.CrawlerOptions{
		Depth:         c.Depth,
		MaxPages:      c.MaxPages,
		Timeout:       c.Timeout,
		Scope:         c.Scope,
		Headless:      c.Headless,
		Proxy:         c.Proxy,
		ProxyInsecure: c.ProxyInsecure,
		Concurrency:   c.Concurrency,
		AllowPrivate:  c.DangerousAllowPrivate,
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
		// Log the captured count BEFORE augmentation/JS analysis so the number
		// reflects what the crawler observed, not the post-static-analysis
		// total. Matches ScanCmd.Run's ordering.
		fmt.Fprintf(os.Stderr, "captured %d requests\n", len(requests)) //nolint:gosec // G705: writing to stderr, not web response
	}

	// NOTE: running `crawl` (with --analyze-js) followed by `generate` (also
	// with --analyze-js, the default) does NOT re-analyze the same JS bundles.
	// AnalyzeJS's idempotency guard (crawl.AnyStaticSource) detects the
	// static:js entries this stage writes into the capture and short-circuits the
	// second analysis, so `crawl | generate` is byte-identical to a single `scan`.
	requests = pipeline.AnalyzeJS(bs.ctx, requests, pipeline.AugmentOptions{
		AnalyzeJS:       c.AnalyzeJS,
		FetchSourcemaps: c.FetchSourcemaps,
		AllowPrivate:    c.DangerousAllowPrivate,
		Status:          statusWriter(c.Verbose),
		WarnError:       os.Stderr,
	})

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
	APIType                string  `arg:"" enum:"rest,wsdl,graphql,grpc" help:"API type to generate (rest, wsdl, graphql, grpc)"`
	Capture                string  `arg:"" help:"Capture file path"`
	Output                 string  `short:"o" help:"Output file path"`
	Confidence             float64 `default:"0.5" help:"Minimum confidence threshold"`
	Probe                  bool    `default:"true" help:"Enable active probing of classified endpoints (OPTIONS/schema/WSDL-fetch/GraphQL introspection). Note: JS-bundle replay extraction runs only in 'scan', which has a live target URL to re-fetch bundles from; 'generate' works offline from an existing capture and cannot run it."`
	Deduplicate            bool    `default:"true" help:"Deduplicate classified endpoints before probing"`
	DangerousAllowPrivate  bool    `help:"Disable SSRF protection on the probe path (OPTIONS/schema/WSDL-fetch/GraphQL introspection) for private/localhost targets. WARNING: Do not use on production systems." name:"dangerous-allow-private"`
	GRPCInsecureSkipVerify bool    `help:"Skip TLS certificate verification when probing gRPC server reflection over TLS (for self-signed/internal-CA targets). Default: verify." name:"grpc-insecure-skip-verify"`
	Verbose                bool    `short:"v" help:"Enable verbose logging"`
	AnalyzeJS              bool    `name:"analyze-js"       default:"true"  help:"Statically analyze JS bundles in the imported capture (when present)."`
	FetchSourcemaps        bool    `name:"fetch-sourcemaps" default:"false" help:"When --analyze-js is set, fetch .js.map sourcemaps referenced via //# sourceMappingURL= comments. Default false on generate (offline-friendly)."`

	SlugOptions
}

// maxCaptureSize is the maximum capture file size (100MB).
const maxCaptureSize = 100 * 1024 * 1024

// Run executes the generate command.
func (c *GenerateCmd) Run() (err error) {
	if err := validateSlugThreshold(c.APIType, c.MergeSlugs, c.SlugThreshold); err != nil {
		return err
	}

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

	// Augment captured requests with static-HTML form analysis + JS bundle
	// static analysis in the canonical forms-then-jsstatic order (see
	// pipeline.Augment). Captures produced by crawl/import (which don't run form
	// extraction inline) get the same treatment as captures produced by scan.
	requests = pipeline.Augment(ctx, requests, pipeline.AugmentOptions{
		AnalyzeJS:       c.AnalyzeJS,
		FetchSourcemaps: c.FetchSourcemaps,
		AllowPrivate:    c.DangerousAllowPrivate,
		Status:          statusWriter(c.Verbose),
		WarnError:       os.Stderr,
	})

	warnSSRFDisabled(c.DangerousAllowPrivate, c.Probe)

	spec, err := pipeline.ClassifyProbeGenerate(ctx, requests, pipeline.Options{
		APIType:                c.APIType,
		Confidence:             c.Confidence,
		Probe:                  c.Probe,
		Deduplicate:            c.Deduplicate,
		AllowPrivate:           c.DangerousAllowPrivate,
		GRPCInsecureSkipVerify: c.GRPCInsecureSkipVerify,
		MergeSlugs:             c.MergeSlugs,
		SlugThreshold:          c.SlugThreshold,
		Status:                 statusWriter(c.Verbose),
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
	URL                    string  `arg:"" help:"Target URL to scan"`
	APIType                string  `default:"auto" enum:"auto,rest,wsdl,graphql,grpc" help:"API type to generate (auto detects from traffic; grpc requires explicit selection)" name:"api-type"`
	Confidence             float64 `default:"0.5" help:"Minimum confidence threshold"`
	Probe                  bool    `default:"true" help:"Enable endpoint probing"`
	Deduplicate            bool    `default:"true" help:"Deduplicate classified endpoints before probing"`
	DangerousAllowPrivate  bool    `help:"Disable SSRF protection for crawling and probes, allowing private/localhost targets (localhost, 127.0.0.1, RFC1918, link-local). Required when the seed URL is a private host, otherwise the crawl exits with an error and captures nothing. WARNING: Do not use on production systems." name:"dangerous-allow-private"`
	GRPCInsecureSkipVerify bool    `help:"Skip TLS certificate verification when probing gRPC server reflection over TLS (for self-signed/internal-CA targets). Default: verify." name:"grpc-insecure-skip-verify"`

	CrawlOptions
	SlugOptions
}

// Run executes the scan command (crawl + generate pipeline).
func (c *ScanCmd) Run() error { //nolint:gocyclo // top-level orchestration
	if err := validateURL(c.URL); err != nil {
		return err
	}

	if err := validateSlugThreshold(c.APIType, c.MergeSlugs, c.SlugThreshold); err != nil {
		return err
	}

	bs, err := setupBrowserAndSignals(c.Header, c.CrawlOptions, crawl.CrawlerOptions{
		Depth:         c.Depth,
		MaxPages:      c.MaxPages,
		Timeout:       c.Timeout,
		Scope:         c.Scope,
		Headless:      c.Headless,
		Proxy:         c.Proxy,
		ProxyInsecure: c.ProxyInsecure,
		Concurrency:   c.Concurrency,
		AllowPrivate:  c.DangerousAllowPrivate,
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

	// Augment captured requests with static-HTML form analysis + JS bundle
	// static analysis in the canonical forms-then-jsstatic order (see
	// pipeline.Augment). Same helper used by GenerateCmd.Run — the order
	// contract is centralized to prevent the two commands from silently
	// diverging.
	requests = pipeline.Augment(bs.ctx, requests, pipeline.AugmentOptions{
		AnalyzeJS:       c.AnalyzeJS,
		FetchSourcemaps: c.FetchSourcemaps,
		AllowPrivate:    c.DangerousAllowPrivate,
		Status:          statusWriter(c.Verbose),
		WarnError:       os.Stderr,
	})

	// Resolve the API type up front (when auto) so the verbose "detected API
	// type" line reflects the traffic-derived type *before* any WSDL promotion,
	// matching the pre-refactor ordering. The resolved type is then passed
	// explicitly into ResolveAndGenerate, which skips re-detection for a
	// non-auto type. Passing the resolved (non-auto) type is precisely what
	// prevents a second DetectAPIType pass inside ResolveAndGenerate — the two
	// detection sites are coupled, so keep them in sync if either changes.
	apiType := c.APIType
	if apiType == pipeline.APITypeAuto {
		apiType = pipeline.DetectAPIType(requests, c.Confidence)
		if c.Verbose {
			fmt.Fprintf(os.Stderr, "detected API type: %s\n", apiType) //nolint:gosec // G705: writing to stderr, not web response
		}
	}

	// Create a fresh signal context for the generate phase. If a signal
	// interrupted the crawl, bs.ctx is already canceled — doCrawl swallowed
	// the error and returned partial results. Using the canceled context
	// would cause ClassifyProbeGenerate's probing (and WSDL probing) to bail out immediately.
	genCtx, genStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer genStop()

	// Emit the SSRF-disabled warning before any active probing so the notice
	// always precedes outbound requests to private/internal networks. The WSDL
	// probe inside ResolveAndGenerate is the first such activity in the scan
	// phase, so the warning must come first (matching GenerateCmd.Run, which
	// warns before probing).
	warnSSRFDisabled(c.DangerousAllowPrivate, c.Probe)

	// Run the shared detect → wsdl-resolve → (JS-replay) → classify/probe/generate
	// sequence. The afterWSDL hook keeps JS-replay in its CLI-specific position:
	// after WSDL resolution and before classification. JS-replay re-fetches
	// bundle-extracted URLs with raw HTTP to bypass SPA catch-all routing; it is
	// gated on both c.AnalyzeJS (so --analyze-js=false suppresses the JS-bundle
	// rescan) and c.Probe (so --probe=false stays passive — see
	// maybeReplayJSExtracted), and is CLI-only (the SDK passes a nil AfterWSDL hook).
	spec, apiType, foundWSDL, _, err := pipeline.ResolveAndGenerate(genCtx, requests, pipeline.ScanOptions{
		TargetURL:              c.URL,
		APIType:                apiType,
		Confidence:             c.Confidence,
		Probe:                  c.Probe,
		Deduplicate:            c.Deduplicate,
		AllowPrivate:           c.DangerousAllowPrivate,
		GRPCInsecureSkipVerify: c.GRPCInsecureSkipVerify,
		MergeSlugs:             c.MergeSlugs,
		SlugThreshold:          c.SlugThreshold,
		Status:                 statusWriter(c.Verbose),
		AfterWSDL: func(ctx context.Context, reqs []crawl.ObservedRequest) []crawl.ObservedRequest {
			return maybeReplayJSExtracted(ctx, reqs, c.Probe && c.AnalyzeJS, crawl.JSReplayConfig{
				Headers:      bs.opts.Headers,
				TargetURL:    c.URL,
				AllowPrivate: c.DangerousAllowPrivate,
				Verbose:      c.Verbose,
				Stderr:       os.Stderr,
			})
		},
	})
	if err != nil {
		return err
	}

	if foundWSDL && c.Verbose {
		fmt.Fprintf(os.Stderr, "discovered WSDL document at %s?wsdl\n", c.URL)
	}
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "generating %s spec\n", apiTypeDisplayName(apiType)) //nolint:gosec // G705: writing to stderr, not web response
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

// maybeReplayJSExtracted is the probe-gated wrapper around
// crawl.ReplayJSExtracted. When probe is false, it returns requests unchanged
// without making any outbound HTTP — preserving the user's --probe=false
// expectation that the scan stays passive (capture-only). When probe is true,
// it forwards to crawl.ReplayJSExtracted with the supplied config.
//
// Pulled out of ScanCmd.Run so the gate's contract is unit-testable without
// standing up a headless browser. A regression that calls
// crawl.ReplayJSExtracted directly (bypassing this gate) would re-introduce
// the surprise outbound HTTP behavior CodeRabbit flagged in iter-12 (CR-1).
func maybeReplayJSExtracted(ctx context.Context, requests []crawl.ObservedRequest, probe bool, cfg crawl.JSReplayConfig) []crawl.ObservedRequest {
	if !probe {
		return requests
	}
	return crawl.ReplayJSExtracted(ctx, requests, cfg)
}

// validateSlugThreshold rejects --slug-threshold < 2 when --merge-slugs is on.
// It runs early in GenerateCmd.Run and ScanCmd.Run so crawl/file I/O never
// starts on an invalid flag combination. It delegates to
// pipeline.ValidateSlugThreshold — the shared source of truth also enforced
// inside the pipeline for SDK/direct callers.
func validateSlugThreshold(apiType string, mergeSlugs bool, slugThreshold int) error {
	return pipeline.ValidateSlugThreshold(apiType, mergeSlugs, slugThreshold)
}

// apiTypeDisplayName returns a human-readable display name for an API type.
func apiTypeDisplayName(apiType string) string {
	switch apiType {
	case pipeline.APITypeREST:
		return "REST"
	case pipeline.APITypeWSDL:
		return "WSDL"
	case pipeline.APITypeGraphQL:
		return "GraphQL"
	case pipeline.APITypeGRPC:
		return "gRPC"
	default:
		return apiType
	}
}

// statusWriter returns os.Stderr when verbose is true, otherwise nil.
// Used to forward verbose progress output to the pipeline package.
func statusWriter(verbose bool) io.Writer {
	if verbose {
		return os.Stderr
	}
	return nil
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
