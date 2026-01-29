# Vespasian Backend Architecture Assessment

> **For Claude:** REQUIRED SUB-SKILL: Use this architecture as the technical specification for implementation.

**Goal:** Comprehensive API surface enumeration tool with plugin architecture supporting multiple probe types

**Architecture:** Standalone Go implementation with static plugin registration (init() pattern), generic registry from Augustus, and YAML template system from Hadrian patterns

**Tech Stack:** Go 1.24, Cobra CLI, chromedp (headless browser), grpcurl, gorilla/websocket, getkin/kin-openapi

---

## Table of Contents

1. [Package Organization](#1-package-organization)
2. [Concurrency Patterns](#2-concurrency-patterns)
3. [HTTP Client Design](#3-http-client-design)
4. [Error Handling Patterns](#4-error-handling-patterns)
5. [Configuration Loading](#5-configuration-loading)
6. [CLI Design](#6-cli-design)
7. [Interface Design](#7-interface-design)
8. [Registry Thread-Safety](#8-registry-thread-safety)
9. [Testing Patterns](#9-testing-patterns)
10. [Dependencies Assessment](#10-dependencies-assessment)
11. [Implementation Guidelines](#11-implementation-guidelines)

---

## 1. Package Organization

### Directory Structure

Based on `structuring-go-projects` skill and Praetorian conventions:

```
vespasian/
├── cmd/
│   └── vespasian/
│       └── main.go              # THIN: calls runner.Run() only
├── pkg/
│   ├── runner/                  # CLI logic (Cobra commands)
│   │   ├── runner.go            # Root command, Execute()
│   │   ├── scan.go              # Main scan subcommand
│   │   ├── list.go              # List probes subcommand
│   │   └── options.go           # Shared CLI flags
│   ├── probes/                  # Probe interfaces and registry
│   │   ├── probe.go             # Core Probe interface
│   │   ├── registry.go          # Global ProbeRegistry (from Augustus)
│   │   └── types.go             # Shared types (APIEndpoint, etc.)
│   ├── http/                    # HTTP crawling and client
│   │   ├── client.go            # HTTP client with rate limiting
│   │   ├── crawler.go           # Standard HTTP crawler
│   │   ├── headless.go          # Headless browser (chromedp)
│   │   └── js/
│   │       └── parser.go        # JavaScript endpoint extraction
│   ├── protocols/               # Non-HTTP protocol probes
│   │   ├── grpc/
│   │   │   └── reflection.go    # gRPC reflection client
│   │   └── websocket/
│   │       └── enumeration.go   # WebSocket discovery
│   ├── specs/                   # API specification probes
│   │   ├── openapi/
│   │   │   └── probe.go         # OpenAPI/Swagger parser
│   │   ├── graphql/
│   │   │   └── probe.go         # GraphQL introspection
│   │   └── wsdl/
│   │       └── probe.go         # SOAP WSDL parser
│   ├── config/                  # Configuration management
│   │   ├── config.go            # Main config struct
│   │   └── loader.go            # YAML/flag merging
│   ├── discovery/               # Output types and formatters
│   │   ├── endpoint.go          # APIEndpoint struct
│   │   └── output.go            # JSON/JSONL/table formatters
│   └── matchers/                # Pattern matching (from Hadrian)
│       ├── matcher.go           # Matcher interface
│       ├── word.go              # Word matcher
│       ├── regex.go             # Regex matcher
│       └── status.go            # Status code matcher
├── internal/                    # Private utilities
│   └── util/
│       ├── backoff.go           # Exponential backoff
│       └── ratelimit.go         # Rate limiter wrapper
├── templates/                   # YAML probe templates
│   ├── specs/
│   │   ├── openapi-detection.yaml
│   │   └── graphql-detection.yaml
│   └── discovery/
│       └── common-paths.yaml
├── testdata/                    # Test fixtures
│   ├── specs/
│   │   ├── petstore-openapi3.yaml
│   │   └── graphql-schema.json
│   └── responses/
│       └── swagger-response.json
└── go.mod
```

### Import Boundaries

**Strict dependency direction (no cycles):**

```
cmd/vespasian
    └── pkg/runner
        ├── pkg/probes (interfaces)
        ├── pkg/config
        └── pkg/discovery

pkg/runner
    └── pkg/http, pkg/protocols, pkg/specs (probe implementations)
        └── pkg/probes (base types)
            └── pkg/discovery (output types)

pkg/http, pkg/specs, pkg/protocols
    └── pkg/matchers
    └── internal/util
```

**Key rules:**
- `cmd/` imports only `pkg/runner`
- `pkg/probes` defines interfaces, no implementations
- Implementations in `pkg/http`, `pkg/specs`, `pkg/protocols` import `pkg/probes`
- `internal/` used for non-exported utilities

---

## 2. Concurrency Patterns

### Pattern: errgroup + Semaphore (Recommended)

Based on `go-errgroup-concurrency` and `implementing-go-semaphore-pools` skills.

```go
package runner

import (
    "context"
    "golang.org/x/sync/errgroup"
    "golang.org/x/sync/semaphore"
)

const (
    // Concurrency limits by workload type
    ConcurrencyCrawl    = 10   // HTTP crawling (I/O bound)
    ConcurrencySpec     = 5    // Spec parsing (CPU bound)
    ConcurrencyProtocol = 20   // Protocol probes (network bound)
)

// ScanTargets runs probes concurrently with bounded parallelism.
func ScanTargets(ctx context.Context, targets []string, probes []probes.Probe, maxWorkers int) ([]discovery.APIEndpoint, error) {
    g, ctx := errgroup.WithContext(ctx)
    sem := semaphore.NewWeighted(int64(maxWorkers))

    results := make(chan discovery.APIEndpoint, len(targets)*10)
    var mu sync.Mutex
    var allEndpoints []discovery.APIEndpoint

    // Collector goroutine
    g.Go(func() error {
        for endpoint := range results {
            mu.Lock()
            allEndpoints = append(allEndpoints, endpoint)
            mu.Unlock()
        }
        return nil
    })

    for _, target := range targets {
        target := target // Capture loop variable (Go < 1.22)

        // Acquire semaphore BEFORE spawning goroutine
        if err := sem.Acquire(ctx, 1); err != nil {
            return nil, err
        }

        g.Go(func() error {
            defer sem.Release(1)
            return runProbesForTarget(ctx, target, probes, results)
        })
    }

    // Wait for all workers, then close results channel
    if err := g.Wait(); err != nil {
        close(results)
        return nil, err
    }
    close(results)

    return allEndpoints, nil
}

func runProbesForTarget(ctx context.Context, target string, probes []probes.Probe, results chan<- discovery.APIEndpoint) error {
    url, err := url.Parse(target)
    if err != nil {
        return fmt.Errorf("invalid target URL %s: %w", target, err)
    }

    for _, probe := range probes {
        // Check if probe applies to this target
        if !probe.Applies(url) {
            continue
        }

        // Check context cancellation
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        endpoints, err := probe.Discover(ctx, url)
        if err != nil {
            // Log and continue - don't fail entire scan
            slog.Warn("probe failed", "probe", probe.Name(), "target", target, "error", err)
            continue
        }

        for _, ep := range endpoints {
            results <- ep
        }
    }

    return nil
}
```

### Stage-Specific Worker Multipliers

Following TruffleHog patterns for multi-stage pipelines:

```go
const (
    baseWorkers = 10

    // Stage multipliers based on workload type
    crawlMultiplier     = 3  // I/O bound: 30 workers for HTTP crawling
    specMultiplier      = 1  // CPU bound: 10 workers for spec parsing
    protocolMultiplier  = 2  // Network bound: 20 workers for gRPC/WebSocket
    headlessMultiplier  = 1  // Resource heavy: 10 workers for headless browser
)

func getConcurrency(probeType string) int {
    switch probeType {
    case "crawler":
        return baseWorkers * crawlMultiplier
    case "spec":
        return baseWorkers * specMultiplier
    case "protocol":
        return baseWorkers * protocolMultiplier
    case "headless":
        return baseWorkers * headlessMultiplier
    default:
        return baseWorkers
    }
}
```

---

## 3. HTTP Client Design

### Connection Pooling and Timeouts

```go
package http

import (
    "context"
    "crypto/tls"
    "net"
    "net/http"
    "time"

    "golang.org/x/time/rate"
)

// ClientConfig configures HTTP client behavior.
type ClientConfig struct {
    // Timeouts
    Timeout            time.Duration // Total request timeout
    DialTimeout        time.Duration // TCP connection timeout
    TLSHandshakeTimeout time.Duration // TLS negotiation timeout
    IdleConnTimeout    time.Duration // Keep-alive connection timeout

    // Connection pooling
    MaxIdleConns        int  // Total idle connections across all hosts
    MaxIdleConnsPerHost int  // Idle connections per host
    MaxConnsPerHost     int  // Max connections per host (0 = unlimited)

    // Rate limiting
    RateLimit     float64 // Requests per second (0 = disabled)
    RateBurst     int     // Burst capacity

    // TLS
    InsecureSkipVerify bool

    // User agent
    UserAgent string
}

// DefaultClientConfig returns production-safe defaults.
func DefaultClientConfig() ClientConfig {
    return ClientConfig{
        Timeout:             30 * time.Second,
        DialTimeout:         10 * time.Second,
        TLSHandshakeTimeout: 10 * time.Second,
        IdleConnTimeout:     90 * time.Second,
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        MaxConnsPerHost:     25,
        RateLimit:           50, // 50 req/sec default
        RateBurst:           10,
        InsecureSkipVerify:  false,
        UserAgent:           "Vespasian/1.0",
    }
}

// Client wraps http.Client with rate limiting and observability.
type Client struct {
    client      *http.Client
    rateLimiter *rate.Limiter
    userAgent   string
}

// NewClient creates a configured HTTP client.
func NewClient(cfg ClientConfig) *Client {
    transport := &http.Transport{
        DialContext: (&net.Dialer{
            Timeout:   cfg.DialTimeout,
            KeepAlive: 30 * time.Second,
        }).DialContext,
        TLSHandshakeTimeout: cfg.TLSHandshakeTimeout,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: cfg.InsecureSkipVerify,
        },
        MaxIdleConns:        cfg.MaxIdleConns,
        MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
        MaxConnsPerHost:     cfg.MaxConnsPerHost,
        IdleConnTimeout:     cfg.IdleConnTimeout,
    }

    var limiter *rate.Limiter
    if cfg.RateLimit > 0 {
        limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateBurst)
    }

    return &Client{
        client: &http.Client{
            Transport: transport,
            Timeout:   cfg.Timeout,
        },
        rateLimiter: limiter,
        userAgent:   cfg.UserAgent,
    }
}

// Do executes request with rate limiting.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
    // Apply rate limiting
    if c.rateLimiter != nil {
        if err := c.rateLimiter.Wait(ctx); err != nil {
            return nil, fmt.Errorf("rate limiter: %w", err)
        }
    }

    // Set user agent
    if c.userAgent != "" && req.Header.Get("User-Agent") == "" {
        req.Header.Set("User-Agent", c.userAgent)
    }

    // Execute request with context
    req = req.WithContext(ctx)
    return c.client.Do(req)
}
```

### Backoff Pattern (from Hadrian)

```go
package util

import (
    "context"
    "math"
    "time"
)

// Backoff implements exponential backoff with jitter.
type Backoff struct {
    StatusCodes  []int         // Status codes that trigger backoff
    BodyPatterns []string      // Response body patterns that trigger backoff
    BaseDelay    time.Duration // Initial delay
    MaxDelay     time.Duration // Maximum delay
    MaxRetries   int           // Maximum retry attempts
    Factor       float64       // Multiplier (default 2.0)
}

// DefaultBackoff returns sensible defaults.
func DefaultBackoff() Backoff {
    return Backoff{
        StatusCodes:  []int{429, 503, 502},
        BaseDelay:    1 * time.Second,
        MaxDelay:     30 * time.Second,
        MaxRetries:   5,
        Factor:       2.0,
    }
}

// Wait calculates and waits for the next backoff interval.
func (b *Backoff) Wait(ctx context.Context, attempt int) error {
    if attempt >= b.MaxRetries {
        return fmt.Errorf("max retries (%d) exceeded", b.MaxRetries)
    }

    delay := float64(b.BaseDelay) * math.Pow(b.Factor, float64(attempt))
    if delay > float64(b.MaxDelay) {
        delay = float64(b.MaxDelay)
    }

    // Add jitter (10-20%)
    jitter := delay * (0.1 + 0.1*rand.Float64())
    totalDelay := time.Duration(delay + jitter)

    select {
    case <-ctx.Done():
        return ctx.Err()
    case <-time.After(totalDelay):
        return nil
    }
}

// ShouldRetry checks if status/body indicates retry needed.
func (b *Backoff) ShouldRetry(statusCode int, body []byte) bool {
    for _, code := range b.StatusCodes {
        if statusCode == code {
            return true
        }
    }

    bodyStr := string(body)
    for _, pattern := range b.BodyPatterns {
        if strings.Contains(bodyStr, pattern) {
            return true
        }
    }

    return false
}
```

---

## 4. Error Handling Patterns

Based on `error-handling-patterns` skill.

### Custom Error Types

```go
package probes

import (
    "errors"
    "fmt"
)

// Sentinel errors for type-based checking.
var (
    ErrProbeNotFound     = errors.New("probe not found")
    ErrTargetUnreachable = errors.New("target unreachable")
    ErrRateLimited       = errors.New("rate limited")
    ErrAuthRequired      = errors.New("authentication required")
    ErrInvalidSpec       = errors.New("invalid specification")
)

// ProbeError wraps errors with probe context.
type ProbeError struct {
    Probe   string // Probe name
    Target  string // Target URL
    Cause   error  // Underlying error
    Message string // Human-readable message
}

func (e *ProbeError) Error() string {
    if e.Cause != nil {
        return fmt.Sprintf("probe %s on %s: %s: %v", e.Probe, e.Target, e.Message, e.Cause)
    }
    return fmt.Sprintf("probe %s on %s: %s", e.Probe, e.Target, e.Message)
}

func (e *ProbeError) Unwrap() error {
    return e.Cause
}

// NewProbeError creates a contextual probe error.
func NewProbeError(probe, target, message string, cause error) *ProbeError {
    return &ProbeError{
        Probe:   probe,
        Target:  target,
        Cause:   cause,
        Message: message,
    }
}

// IsRetryable checks if error is transient.
func IsRetryable(err error) bool {
    if errors.Is(err, ErrRateLimited) {
        return true
    }
    if errors.Is(err, ErrTargetUnreachable) {
        return true
    }
    // Network errors are retryable
    var netErr net.Error
    if errors.As(err, &netErr) && netErr.Temporary() {
        return true
    }
    return false
}
```

### Error Aggregation for Batch Operations

```go
package discovery

import (
    "errors"
    "strings"
)

// AggregateError collects multiple errors.
type AggregateError struct {
    Errors []error
}

func (e *AggregateError) Error() string {
    if len(e.Errors) == 1 {
        return e.Errors[0].Error()
    }

    var sb strings.Builder
    sb.WriteString(fmt.Sprintf("%d errors occurred:\n", len(e.Errors)))
    for i, err := range e.Errors {
        sb.WriteString(fmt.Sprintf("  [%d] %v\n", i+1, err))
    }
    return sb.String()
}

func (e *AggregateError) Add(err error) {
    if err != nil {
        e.Errors = append(e.Errors, err)
    }
}

func (e *AggregateError) HasErrors() bool {
    return len(e.Errors) > 0
}

func (e *AggregateError) Unwrap() []error {
    return e.Errors
}
```

---

## 5. Configuration Loading

### Config Structure

```go
package config

import (
    "io"
    "os"
    "time"

    "gopkg.in/yaml.v3"
)

// Config holds all Vespasian configuration.
type Config struct {
    // Target selection
    Targets     []string `yaml:"targets"`
    TargetFile  string   `yaml:"target_file"`

    // Probe selection
    EnabledProbes  []string `yaml:"enabled_probes"`
    DisabledProbes []string `yaml:"disabled_probes"`

    // Concurrency
    Concurrency int           `yaml:"concurrency"`
    Timeout     time.Duration `yaml:"timeout"`

    // Rate limiting
    RateLimit float64 `yaml:"rate_limit"`
    RateBurst int     `yaml:"rate_burst"`

    // HTTP options
    HTTP HTTPConfig `yaml:"http"`

    // Headless browser
    Headless HeadlessConfig `yaml:"headless"`

    // Output
    Output OutputConfig `yaml:"output"`

    // Logging
    LogLevel string `yaml:"log_level"`
    Verbose  bool   `yaml:"verbose"`
}

type HTTPConfig struct {
    UserAgent          string        `yaml:"user_agent"`
    Headers            map[string]string `yaml:"headers"`
    InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
    MaxRedirects       int           `yaml:"max_redirects"`
    Timeout            time.Duration `yaml:"timeout"`
}

type HeadlessConfig struct {
    Enabled         bool          `yaml:"enabled"`
    ChromePath      string        `yaml:"chrome_path"`
    Timeout         time.Duration `yaml:"timeout"`
    WaitAfterLoad   time.Duration `yaml:"wait_after_load"`
    CaptureXHR      bool          `yaml:"capture_xhr"`
    CaptureWebSocket bool         `yaml:"capture_websocket"`
}

type OutputConfig struct {
    Format  string `yaml:"format"` // json, jsonl, table, csv
    File    string `yaml:"file"`
    Verbose bool   `yaml:"verbose"`
}

// DefaultConfig returns production-safe defaults.
func DefaultConfig() *Config {
    return &Config{
        Concurrency: 10,
        Timeout:     30 * time.Second,
        RateLimit:   50,
        RateBurst:   10,
        HTTP: HTTPConfig{
            UserAgent:    "Vespasian/1.0",
            MaxRedirects: 10,
            Timeout:      30 * time.Second,
        },
        Headless: HeadlessConfig{
            Enabled:       false,
            Timeout:       60 * time.Second,
            WaitAfterLoad: 2 * time.Second,
            CaptureXHR:    true,
        },
        Output: OutputConfig{
            Format: "jsonl",
        },
        LogLevel: "info",
    }
}

// LoadFromFile loads config from YAML file.
func LoadFromFile(path string) (*Config, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, fmt.Errorf("open config file: %w", err)
    }
    defer f.Close()

    return LoadFromReader(f)
}

// LoadFromReader loads config from reader.
func LoadFromReader(r io.Reader) (*Config, error) {
    cfg := DefaultConfig()

    decoder := yaml.NewDecoder(r)
    if err := decoder.Decode(cfg); err != nil {
        return nil, fmt.Errorf("parse config: %w", err)
    }

    return cfg, nil
}
```

### CLI Flag Merging

```go
package config

import (
    "github.com/spf13/pflag"
    "github.com/spf13/viper"
)

// BindFlags binds CLI flags to config with proper precedence.
// Order: CLI flags > env vars > config file > defaults
func BindFlags(flags *pflag.FlagSet) error {
    viper.SetEnvPrefix("VESPASIAN")
    viper.AutomaticEnv()

    // Bind each flag
    if err := viper.BindPFlags(flags); err != nil {
        return fmt.Errorf("bind flags: %w", err)
    }

    return nil
}

// Merge applies viper values to config.
func (c *Config) Merge(v *viper.Viper) {
    if v.IsSet("concurrency") {
        c.Concurrency = v.GetInt("concurrency")
    }
    if v.IsSet("timeout") {
        c.Timeout = v.GetDuration("timeout")
    }
    if v.IsSet("rate-limit") {
        c.RateLimit = v.GetFloat64("rate-limit")
    }
    // ... additional fields
}
```

---

## 6. CLI Design

Based on `go-best-practices` skill.

### Thin main.go

```go
// cmd/vespasian/main.go
package main

import (
    "os"

    "github.com/praetorian-inc/vespasian/pkg/runner"
)

func main() {
    if err := runner.Run(); err != nil {
        os.Exit(1)
    }
}
```

### Runner with Cobra

```go
// pkg/runner/runner.go
package runner

import (
    "fmt"
    "os"

    "github.com/spf13/cobra"
    "github.com/spf13/viper"
)

var (
    cfgFile string
    verbose bool
)

var rootCmd = &cobra.Command{
    Use:   "vespasian",
    Short: "API surface enumeration tool",
    Long: `Vespasian discovers API endpoints through multiple techniques:
  - HTTP crawling (standard and headless browser)
  - OpenAPI/Swagger specification parsing
  - GraphQL introspection
  - gRPC reflection
  - WebSocket enumeration
  - JavaScript parsing for endpoints`,
}

func init() {
    cobra.OnInitialize(initConfig)

    // Global flags
    rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default $HOME/.vespasian.yaml)")
    rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

    // Add subcommands
    rootCmd.AddCommand(scanCmd)
    rootCmd.AddCommand(listCmd)
    rootCmd.AddCommand(versionCmd)
}

func initConfig() {
    if cfgFile != "" {
        viper.SetConfigFile(cfgFile)
    } else {
        home, err := os.UserHomeDir()
        cobra.CheckErr(err)

        viper.AddConfigPath(home)
        viper.AddConfigPath(".")
        viper.SetConfigType("yaml")
        viper.SetConfigName(".vespasian")
    }

    viper.AutomaticEnv()

    if err := viper.ReadInConfig(); err == nil {
        fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
    }
}

// Run executes the CLI.
func Run() error {
    return rootCmd.Execute()
}
```

### Scan Command (Extracted Logic)

```go
// pkg/runner/scan.go
package runner

import (
    "context"
    "os"
    "os/signal"
    "syscall"

    "github.com/spf13/cobra"
    "github.com/praetorian-inc/vespasian/pkg/config"
    "github.com/praetorian-inc/vespasian/pkg/discovery"
    "github.com/praetorian-inc/vespasian/pkg/probes"
)

var scanCmd = &cobra.Command{
    Use:   "scan [targets...]",
    Short: "Scan targets for API endpoints",
    Long:  `Discover API endpoints using enabled probes.`,
    Args:  cobra.MinimumNArgs(1),
    RunE:  runScan,  // Named function (not inline)
}

func init() {
    flags := scanCmd.Flags()
    flags.IntP("concurrency", "c", 10, "maximum concurrent requests")
    flags.Float64P("rate-limit", "r", 50, "requests per second (0 = unlimited)")
    flags.StringP("output", "o", "", "output file (default: stdout)")
    flags.StringP("format", "f", "jsonl", "output format (json, jsonl, table, csv)")
    flags.StringSliceP("probe", "p", nil, "enable specific probes (default: all)")
    flags.Bool("headless", false, "enable headless browser crawling")
    flags.Duration("timeout", 30*time.Second, "request timeout")
}

func runScan(cmd *cobra.Command, args []string) error {
    // Setup context with cancellation
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Handle interrupt signal
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-sigCh
        cancel()
    }()

    // Load configuration
    cfg := config.DefaultConfig()
    cfg.Targets = args

    // Apply CLI flags
    if err := config.BindFlags(cmd.Flags()); err != nil {
        return fmt.Errorf("bind flags: %w", err)
    }

    // Get enabled probes
    enabledProbes, err := probes.GetEnabledProbes(cfg.EnabledProbes)
    if err != nil {
        return fmt.Errorf("load probes: %w", err)
    }

    // Run scan
    endpoints, err := ScanTargets(ctx, cfg.Targets, enabledProbes, cfg.Concurrency)
    if err != nil {
        return fmt.Errorf("scan failed: %w", err)
    }

    // Output results
    return discovery.WriteOutput(endpoints, cfg.Output)
}
```

---

## 7. Interface Design

### Core Probe Interface

Based on Nerva Plugin interface adapted for HTTP-level discovery:

```go
// pkg/probes/probe.go
package probes

import (
    "context"
    "net/url"

    "github.com/praetorian-inc/vespasian/pkg/discovery"
)

// ProbeType categorizes probe capabilities.
type ProbeType string

const (
    ProbeTypeCrawler  ProbeType = "crawler"   // HTTP crawling
    ProbeTypeSpec     ProbeType = "spec"      // API specifications
    ProbeTypeProtocol ProbeType = "protocol"  // Non-HTTP protocols
    ProbeTypeData     ProbeType = "data"      // File-based discovery
)

// Probe is the core interface for all endpoint discovery methods.
type Probe interface {
    // Name returns the unique probe identifier.
    Name() string

    // Type returns the probe category.
    Type() ProbeType

    // Priority returns execution priority (lower = earlier).
    // Used for ordering within a type (e.g., spec probes run after crawlers).
    Priority() int

    // Applies checks if this probe should run for the given target.
    Applies(target *url.URL) bool

    // Discover executes the probe and returns discovered endpoints.
    Discover(ctx context.Context, target *url.URL) ([]discovery.APIEndpoint, error)
}

// Configurable is an optional interface for probes that accept configuration.
type Configurable interface {
    // Configure applies configuration to the probe.
    Configure(cfg map[string]interface{}) error
}

// Stateful is an optional interface for probes that maintain state across calls.
type Stateful interface {
    // Reset clears internal state.
    Reset()
}
```

### Interface Hierarchy (Specialized Probes)

```go
// pkg/probes/types.go
package probes

import (
    "context"
    "net/url"
)

// HTTPProbe extends Probe for HTTP-based discovery.
type HTTPProbe interface {
    Probe

    // MaxDepth returns maximum crawl depth (for crawlers).
    MaxDepth() int

    // FollowRedirects indicates redirect handling.
    FollowRedirects() bool
}

// SpecProbe extends Probe for API specification parsing.
type SpecProbe interface {
    Probe

    // SpecPaths returns paths to check for specifications.
    // e.g., ["/swagger.json", "/openapi.yaml", "/api-docs"]
    SpecPaths() []string

    // ParseSpec parses raw specification data.
    ParseSpec(ctx context.Context, data []byte, baseURL *url.URL) ([]discovery.APIEndpoint, error)
}

// ProtocolProbe extends Probe for non-HTTP protocols.
type ProtocolProbe interface {
    Probe

    // DefaultPort returns the default port for this protocol.
    DefaultPort() int

    // RequiresTLS indicates if TLS is required.
    RequiresTLS() bool
}
```

### Output Types

```go
// pkg/discovery/endpoint.go
package discovery

import (
    "encoding/json"
    "time"
)

// APIEndpoint represents a discovered API endpoint.
type APIEndpoint struct {
    URL           string            `json:"url"`
    Method        string            `json:"method,omitempty"`
    Protocol      string            `json:"protocol"` // http, graphql, grpc, websocket
    AuthScheme    string            `json:"auth_scheme,omitempty"`
    ContentType   string            `json:"content_type,omitempty"`
    Parameters    []Parameter       `json:"parameters,omitempty"`
    DiscoveredBy  string            `json:"discovered_by"` // probe name
    DiscoveredAt  time.Time         `json:"discovered_at"`
    Metadata      json.RawMessage   `json:"metadata,omitempty"` // Probe-specific data
}

// Parameter represents an API parameter.
type Parameter struct {
    Name     string `json:"name"`
    In       string `json:"in"` // path, query, header, body
    Type     string `json:"type,omitempty"`
    Required bool   `json:"required,omitempty"`
}

// OpenAPIMetadata is spec-specific metadata.
type OpenAPIMetadata struct {
    SpecVersion string   `json:"spec_version"` // 2.0, 3.0.x, 3.1.x
    Info        string   `json:"info,omitempty"`
    Servers     []string `json:"servers,omitempty"`
    Tags        []string `json:"tags,omitempty"`
}

// GraphQLMetadata is GraphQL-specific metadata.
type GraphQLMetadata struct {
    QueryType        string   `json:"query_type,omitempty"` // Query, Mutation, Subscription
    Fields           []string `json:"fields,omitempty"`
    IntrospectionURL string   `json:"introspection_url,omitempty"`
}

// GRPCMetadata is gRPC-specific metadata.
type GRPCMetadata struct {
    Service     string   `json:"service"`
    Methods     []string `json:"methods,omitempty"`
    Package     string   `json:"package,omitempty"`
    Reflection  bool     `json:"reflection"` // Whether discovered via reflection
}

// WebSocketMetadata is WebSocket-specific metadata.
type WebSocketMetadata struct {
    Subprotocols []string `json:"subprotocols,omitempty"`
    Extensions   []string `json:"extensions,omitempty"`
    Origin       string   `json:"origin,omitempty"`
}
```

---

## 8. Registry Thread-Safety

Ported directly from Augustus generic registry:

```go
// pkg/probes/registry.go
package probes

import (
    "fmt"
    "sort"
    "sync"
)

// Config is configuration for probe instantiation.
type Config map[string]interface{}

// Factory creates a Probe instance from configuration.
type Factory func(Config) (Probe, error)

// ErrNotFound is returned when a probe is not registered.
var ErrNotFound = fmt.Errorf("probe not found")

// Registry manages registered probes.
// Thread-safe for concurrent use.
type Registry struct {
    mu        sync.RWMutex
    factories map[string]Factory
    name      string
}

// NewRegistry creates a registry with the given name.
func NewRegistry(name string) *Registry {
    return &Registry{
        factories: make(map[string]Factory),
        name:      name,
    }
}

// Register adds a probe factory.
// Called from init() in probe implementations.
func (r *Registry) Register(name string, factory Factory) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.factories[name] = factory
}

// Get retrieves a factory by name.
func (r *Registry) Get(name string) (Factory, bool) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    f, ok := r.factories[name]
    return f, ok
}

// Create instantiates a probe by name with config.
func (r *Registry) Create(name string, cfg Config) (Probe, error) {
    r.mu.RLock()
    factory, ok := r.factories[name]
    r.mu.RUnlock()

    if !ok {
        return nil, fmt.Errorf("%w: %s in %s registry", ErrNotFound, name, r.name)
    }

    return factory(cfg)
}

// List returns all registered probe names (sorted).
func (r *Registry) List() []string {
    r.mu.RLock()
    defer r.mu.RUnlock()

    names := make([]string, 0, len(r.factories))
    for name := range r.factories {
        names = append(names, name)
    }
    sort.Strings(names)
    return names
}

// Has checks if a probe is registered.
func (r *Registry) Has(name string) bool {
    r.mu.RLock()
    defer r.mu.RUnlock()
    _, ok := r.factories[name]
    return ok
}

// Count returns the number of registered probes.
func (r *Registry) Count() int {
    r.mu.RLock()
    defer r.mu.RUnlock()
    return len(r.factories)
}

// Reset clears all registrations (testing only).
func (r *Registry) Reset() {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.factories = make(map[string]Factory)
}

// Global registry instance.
var ProbeRegistry = NewRegistry("probes")

// Register is a convenience function for the global registry.
func Register(name string, factory Factory) {
    ProbeRegistry.Register(name, factory)
}

// List is a convenience function for the global registry.
func List() []string {
    return ProbeRegistry.List()
}

// Create is a convenience function for the global registry.
func Create(name string, cfg Config) (Probe, error) {
    return ProbeRegistry.Create(name, cfg)
}
```

### Self-Registration Pattern

```go
// pkg/specs/openapi/probe.go
package openapi

import (
    "github.com/praetorian-inc/vespasian/pkg/probes"
)

func init() {
    probes.Register("openapi.SwaggerDetector", func(cfg probes.Config) (probes.Probe, error) {
        return NewSwaggerProbe(cfg)
    })
    probes.Register("openapi.OpenAPIv3", func(cfg probes.Config) (probes.Probe, error) {
        return NewOpenAPIv3Probe(cfg)
    })
}
```

---

## 9. Testing Patterns

### Table-Driven Tests

```go
// pkg/probes/registry_test.go
package probes_test

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/praetorian-inc/vespasian/pkg/probes"
)

func TestRegistry_RegisterAndCreate(t *testing.T) {
    tests := []struct {
        name      string
        probeName string
        factory   probes.Factory
        cfg       probes.Config
        wantErr   bool
    }{
        {
            name:      "register and create probe",
            probeName: "test.Probe",
            factory: func(cfg probes.Config) (probes.Probe, error) {
                return &mockProbe{name: "test"}, nil
            },
            cfg:     nil,
            wantErr: false,
        },
        {
            name:      "create unregistered probe",
            probeName: "nonexistent.Probe",
            factory:   nil, // Don't register
            cfg:       nil,
            wantErr:   true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Reset registry for test isolation
            reg := probes.NewRegistry("test")

            if tt.factory != nil {
                reg.Register(tt.probeName, tt.factory)
            }

            probe, err := reg.Create(tt.probeName, tt.cfg)

            if tt.wantErr {
                require.Error(t, err)
                assert.ErrorIs(t, err, probes.ErrNotFound)
            } else {
                require.NoError(t, err)
                assert.NotNil(t, probe)
            }
        })
    }
}

func TestRegistry_ThreadSafety(t *testing.T) {
    reg := probes.NewRegistry("test")

    // Concurrent registration
    var wg sync.WaitGroup
    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            name := fmt.Sprintf("probe.%d", i)
            reg.Register(name, func(cfg probes.Config) (probes.Probe, error) {
                return &mockProbe{name: name}, nil
            })
        }(i)
    }
    wg.Wait()

    assert.Equal(t, 100, reg.Count())

    // Concurrent reads
    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            name := fmt.Sprintf("probe.%d", i)
            assert.True(t, reg.Has(name))
        }(i)
    }
    wg.Wait()
}
```

### Mock Implementations

```go
// pkg/probes/mock_test.go
package probes_test

import (
    "context"
    "net/url"

    "github.com/praetorian-inc/vespasian/pkg/discovery"
    "github.com/praetorian-inc/vespasian/pkg/probes"
)

type mockProbe struct {
    name      string
    probeType probes.ProbeType
    priority  int
    applies   bool
    endpoints []discovery.APIEndpoint
    err       error
}

func (m *mockProbe) Name() string                      { return m.name }
func (m *mockProbe) Type() probes.ProbeType            { return m.probeType }
func (m *mockProbe) Priority() int                     { return m.priority }
func (m *mockProbe) Applies(target *url.URL) bool      { return m.applies }

func (m *mockProbe) Discover(ctx context.Context, target *url.URL) ([]discovery.APIEndpoint, error) {
    if m.err != nil {
        return nil, m.err
    }
    return m.endpoints, nil
}
```

### Integration Test with Testcontainers (Future)

```go
// pkg/specs/openapi/probe_integration_test.go
//go:build integration

package openapi_test

import (
    "context"
    "testing"

    "github.com/testcontainers/testcontainers-go"
)

func TestOpenAPIProbe_LiveSpec(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping integration test")
    }

    // Start mock API server with OpenAPI spec
    ctx := context.Background()
    // ... testcontainers setup
}
```

---

## 10. Dependencies Assessment

### Required Libraries

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `github.com/getkin/kin-openapi/openapi3` | v0.127.0+ | OpenAPI 3.x parsing | MIT |
| `github.com/fullstorydev/grpcurl` | v1.9.1+ | gRPC reflection client | MIT |
| `github.com/chromedp/chromedp` | v0.10.0+ | Headless Chrome control | MIT |
| `github.com/gorilla/websocket` | v1.5.3+ | WebSocket client | BSD-2-Clause |
| `github.com/spf13/cobra` | v1.8.1+ | CLI framework | Apache-2.0 |
| `github.com/spf13/viper` | v1.19.0+ | Configuration management | MIT |
| `golang.org/x/sync/errgroup` | latest | Error group concurrency | BSD-3-Clause |
| `golang.org/x/sync/semaphore` | latest | Bounded concurrency | BSD-3-Clause |
| `golang.org/x/time/rate` | latest | Rate limiting | BSD-3-Clause |
| `gopkg.in/yaml.v3` | v3.0.1+ | YAML parsing | Apache-2.0 |
| `github.com/stretchr/testify` | v1.9.0+ | Test assertions | MIT |

### License Compatibility

All dependencies use permissive licenses (MIT, Apache-2.0, BSD) compatible with commercial use.

### Version Recommendations

```go
// go.mod additions
require (
    github.com/chromedp/chromedp v0.10.0
    github.com/fullstorydev/grpcurl v1.9.1
    github.com/getkin/kin-openapi v0.127.0
    github.com/gorilla/websocket v1.5.3
    github.com/spf13/cobra v1.8.1
    github.com/spf13/viper v1.19.0
    github.com/stretchr/testify v1.9.0
    golang.org/x/sync v0.8.0
    golang.org/x/time v0.6.0
    gopkg.in/yaml.v3 v3.0.1
)
```

### Indirect Dependencies (Notable)

- `github.com/chromedp/cdproto` - Chrome DevTools Protocol (via chromedp)
- `google.golang.org/grpc` - gRPC core (via grpcurl)
- `google.golang.org/protobuf` - Protocol buffers (via grpcurl)

---

## 11. Implementation Guidelines

### P0 Constraints (Scanner Type)

1. **Go compilation without errors** - All code must compile cleanly
2. **Implements required interfaces** - Probe interface compliance for all probes
3. **Graceful error handling** - No panics in production code
4. **Rate limiting for external APIs** - Prevent target overwhelm
5. **Resource limits** - Bounded memory and connections

### Coding Standards

1. **Function Organization**: Exported first, main logic, helpers last
2. **Early Returns**: Handle errors first, keep happy path flat
3. **Maximum Nesting**: 2 levels maximum
4. **Constructors**: Return interfaces when polymorphism intended
5. **Cobra Commands**: Extract Run logic to named functions

### Verification Commands

```bash
# Compile check
go build ./...

# Lint
golangci-lint run

# Test
go test ./... -race -coverprofile=coverage.out

# Coverage report
go tool cover -html=coverage.out
```

### Exit Criteria

- [ ] All packages compile with `go build ./...`
- [ ] Zero lint errors from `golangci-lint run`
- [ ] 80%+ test coverage on core packages (probes, registry, config)
- [ ] All probes implement Probe interface correctly
- [ ] Rate limiting verified with integration tests
- [ ] Concurrent access tests pass (registry, result collection)

---

## Metadata

```json
{
  "agent": "backend-lead",
  "output_type": "architecture-plan",
  "timestamp": "2026-01-27T00:00:00Z",
  "feature_directory": "/Users/nathansportsman/capabilities/modules/vespasian/.capability-development",
  "skills_invoked": [
    "using-skills",
    "discovering-reusable-code",
    "semantic-code-operations",
    "calibrating-time-estimates",
    "enforcing-evidence-based-analysis",
    "gateway-backend",
    "persisting-agent-outputs",
    "brainstorming",
    "writing-plans",
    "verifying-before-completion",
    "adhering-to-dry",
    "adhering-to-yagni",
    "debugging-systematically"
  ],
  "library_skills_read": [
    ".claude/skill-library/development/capabilities/implementing-go-plugin-registries/SKILL.md",
    ".claude/skill-library/development/backend/implementing-go-semaphore-pools/SKILL.md",
    ".claude/skill-library/development/backend/structuring-go-projects/SKILL.md",
    ".claude/skill-library/development/backend/go-best-practices/SKILL.md",
    ".claude/skill-library/development/backend/go-errgroup-concurrency/SKILL.md",
    ".claude/skill-library/development/error-handling-patterns/SKILL.md"
  ],
  "source_files_verified": [
    "/Users/nathansportsman/capabilities/modules/augustus/pkg/registry/registry.go:72-150",
    "/Users/nathansportsman/capabilities/modules/augustus/pkg/probes/probe.go:1-43",
    "/Users/nathansportsman/capabilities/modules/nerva/pkg/plugins/types.go:345-362",
    "/Users/nathansportsman/capabilities/modules/hadrian/hadrian-api-tester/pkg/templates/template.go:1-129",
    "/Users/nathansportsman/capabilities/modules/vespasian/.capability-development/discovery.md",
    "/Users/nathansportsman/capabilities/modules/vespasian/.capability-development/brainstorming.md"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "backend-developer",
    "context": "Implement according to architecture plan, starting with core registry and probe interfaces"
  }
}
```
