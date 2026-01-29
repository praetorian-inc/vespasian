# Vespasian Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Build a comprehensive API surface enumeration tool with plugin architecture supporting HTTP crawling, JavaScript parsing, and multiple API specification formats (OpenAPI, GraphQL, gRPC, WebSocket, WSDL).

**Architecture:** Standalone Go implementation following Nerva (plugin interface), Augustus (generic registry), and Hadrian (YAML templates) patterns. Static registration via init() with hybrid Go plugins + YAML templates.

**Tech Stack:** Go 1.22+, Kong CLI, net/http, google.golang.org/grpc, gorilla/websocket, yaml.v3

---

## Batch 1: Core Foundation

**Exit Criteria:**
- [ ] 9 files created in pkg/registry/, pkg/probes/, pkg/config/, cmd/vespasian/
- [ ] `go build ./cmd/vespasian` succeeds with exit code 0
- [ ] Registry unit tests pass: `go test ./pkg/registry/... -v`
- [ ] CLI `vespasian --help` displays usage

### T001: Initialize Go Module

**Files:**
- Create: `go.mod`
- Create: `go.sum`

**Step 1: Initialize module**

```bash
cd /Users/nathansportsman/capabilities/modules/vespasian
go mod init github.com/praetorian-inc/vespasian
```

**Step 2: Add initial dependencies**

```bash
go get github.com/alecthomas/kong@latest
go get gopkg.in/yaml.v3@latest
go get golang.org/x/sync@latest
```

**Step 3: Verify**

Run: `cat go.mod`
Expected: Module declaration with dependencies

**Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "feat(vespasian): initialize go module"
```

---

### T002: Implement Generic Registry

**Files:**
- Create: `pkg/registry/registry.go`
- Create: `pkg/registry/registry_test.go`

**Step 1: Write failing test**

```go
// pkg/registry/registry_test.go
package registry_test

import (
    "testing"

    "github.com/praetorian-inc/vespasian/pkg/registry"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

type MockProbe struct {
    name string
}

func (m *MockProbe) Name() string { return m.name }

func TestRegistry_Register_And_Create(t *testing.T) {
    reg := registry.New[*MockProbe]("test-probes")

    reg.Register("mock", func(cfg registry.Config) (*MockProbe, error) {
        return &MockProbe{name: "mock"}, nil
    })

    probe, err := reg.Create("mock", nil)
    require.NoError(t, err)
    assert.Equal(t, "mock", probe.Name())
}

func TestRegistry_List_Sorted(t *testing.T) {
    reg := registry.New[*MockProbe]("test-probes")

    reg.Register("zebra", func(cfg registry.Config) (*MockProbe, error) {
        return &MockProbe{name: "zebra"}, nil
    })
    reg.Register("alpha", func(cfg registry.Config) (*MockProbe, error) {
        return &MockProbe{name: "alpha"}, nil
    })

    names := reg.List()
    assert.Equal(t, []string{"alpha", "zebra"}, names)
}

func TestRegistry_Create_NotFound(t *testing.T) {
    reg := registry.New[*MockProbe]("test-probes")

    _, err := reg.Create("nonexistent", nil)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "probe not found")
}

func TestRegistry_Has(t *testing.T) {
    reg := registry.New[*MockProbe]("test-probes")

    reg.Register("exists", func(cfg registry.Config) (*MockProbe, error) {
        return &MockProbe{}, nil
    })

    assert.True(t, reg.Has("exists"))
    assert.False(t, reg.Has("missing"))
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/registry/... -v`
Expected: FAIL (package doesn't exist)

**Step 3: Write implementation**

```go
// pkg/registry/registry.go
package registry

import (
    "fmt"
    "sort"
    "sync"
)

// Config holds configuration for capability instantiation.
type Config map[string]any

// Registry manages registered capabilities of a specific type.
// Thread-safe via sync.RWMutex. Factory pattern enables concurrent usage.
type Registry[T any] struct {
    mu        sync.RWMutex
    factories map[string]func(Config) (T, error)
    name      string
}

// New creates a new registry with the given name.
func New[T any](name string) *Registry[T] {
    return &Registry[T]{
        factories: make(map[string]func(Config) (T, error)),
        name:      name,
    }
}

// Register adds a factory function for the given name.
// Called from init() in implementation files.
func (r *Registry[T]) Register(name string, factory func(Config) (T, error)) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.factories[name] = factory
}

// Get retrieves a factory function by name.
func (r *Registry[T]) Get(name string) (func(Config) (T, error), bool) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    f, ok := r.factories[name]
    return f, ok
}

// Create instantiates a capability by name with the given config.
// Returns new instance each call (factory pattern, not singleton).
func (r *Registry[T]) Create(name string, cfg Config) (T, error) {
    r.mu.RLock()
    factory, ok := r.factories[name]
    r.mu.RUnlock()

    if !ok {
        var zero T
        return zero, fmt.Errorf("probe not found: %s in %s registry", name, r.name)
    }

    return factory(cfg)
}

// List returns all registered names, sorted alphabetically.
func (r *Registry[T]) List() []string {
    r.mu.RLock()
    defer r.mu.RUnlock()

    names := make([]string, 0, len(r.factories))
    for name := range r.factories {
        names = append(names, name)
    }
    sort.Strings(names)
    return names
}

// Has checks if a capability is registered.
func (r *Registry[T]) Has(name string) bool {
    r.mu.RLock()
    defer r.mu.RUnlock()
    _, ok := r.factories[name]
    return ok
}

// Count returns the number of registered capabilities.
func (r *Registry[T]) Count() int {
    r.mu.RLock()
    defer r.mu.RUnlock()
    return len(r.factories)
}

// Name returns the registry name.
func (r *Registry[T]) Name() string {
    return r.name
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./pkg/registry/... -v`
Expected: PASS (4 tests)

**Step 5: Add testify dependency**

```bash
go get github.com/stretchr/testify@latest
```

**Step 6: Commit**

```bash
git add pkg/registry/
git commit -m "feat(registry): implement generic registry with sync.RWMutex"
```

---

### T003: Define Probe Interface Hierarchy

**Files:**
- Create: `pkg/probes/probe.go`
- Create: `pkg/probes/types.go`
- Create: `pkg/probes/registry.go`
- Create: `pkg/probes/probe_test.go`

**Step 1: Write failing test**

```go
// pkg/probes/probe_test.go
package probes_test

import (
    "context"
    "testing"

    "github.com/praetorian-inc/vespasian/pkg/probes"
    "github.com/praetorian-inc/vespasian/pkg/registry"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

type MockProbe struct{}

func (m *MockProbe) Run(ctx context.Context, target probes.Target, opts probes.ProbeOptions) (*probes.ProbeResult, error) {
    return &probes.ProbeResult{
        Endpoints: []probes.APIEndpoint{{URL: "http://example.com/api", Method: "GET"}},
    }, nil
}

func (m *MockProbe) Name() string                         { return "mock" }
func (m *MockProbe) Category() probes.ProbeCategory       { return probes.CategoryHTTP }
func (m *MockProbe) Priority() int                        { return 100 }
func (m *MockProbe) Accepts(target probes.Target) bool    { return true }

func TestProbe_Interface(t *testing.T) {
    var p probes.Probe = &MockProbe{}
    assert.Equal(t, "mock", p.Name())
    assert.Equal(t, probes.CategoryHTTP, p.Category())
}

func TestProbes_Register_And_Create(t *testing.T) {
    // Reset registry for test isolation
    probes.Registry = registry.New[probes.Probe]("probes")

    probes.Register("test-mock", func(cfg registry.Config) (probes.Probe, error) {
        return &MockProbe{}, nil
    })

    probe, err := probes.Create("test-mock", nil)
    require.NoError(t, err)
    assert.Equal(t, "mock", probe.Name())
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/probes/... -v`
Expected: FAIL (package doesn't exist)

**Step 3: Write probe interface**

```go
// pkg/probes/probe.go
package probes

import (
    "context"
)

// ProbeCategory classifies probes for execution ordering.
type ProbeCategory int

const (
    CategoryHTTP     ProbeCategory = iota // HTTP-based discovery
    CategoryProtocol                       // Non-HTTP protocols (gRPC, WebSocket)
    CategoryData                           // File-based (HAR, mobile) - P2
)

func (c ProbeCategory) String() string {
    switch c {
    case CategoryHTTP:
        return "http"
    case CategoryProtocol:
        return "protocol"
    case CategoryData:
        return "data"
    default:
        return "unknown"
    }
}

// Probe is the base interface for all discovery probes.
type Probe interface {
    // Run executes the probe against a target and returns discovered endpoints.
    Run(ctx context.Context, target Target, opts ProbeOptions) (*ProbeResult, error)

    // Name returns the unique probe identifier.
    Name() string

    // Category returns the probe category (http, protocol, data).
    Category() ProbeCategory

    // Priority returns execution priority (lower = higher priority).
    Priority() int

    // Accepts returns true if the probe can handle the given target.
    Accepts(target Target) bool
}

// HTTPProbe extends Probe for HTTP-based discovery.
type HTTPProbe interface {
    Probe

    // RequiresAuth returns true if the probe needs authentication.
    RequiresAuth() bool

    // HTTPMethods returns HTTP methods the probe uses.
    HTTPMethods() []string
}

// SpecProbe is an HTTPProbe that parses API specifications.
type SpecProbe interface {
    HTTPProbe

    // ParseSpec parses a specification from raw bytes.
    ParseSpec(data []byte) ([]APIEndpoint, error)

    // DetectSpec attempts to locate specification files.
    DetectSpec(ctx context.Context, baseURL string) ([]string, error)
}

// ProtocolProbe extends Probe for non-HTTP protocols.
type ProtocolProbe interface {
    Probe

    // Protocol returns the protocol type (grpc, websocket, etc.)
    Protocol() string

    // DefaultPorts returns common ports for this protocol.
    DefaultPorts() []int
}
```

**Step 4: Write types**

```go
// pkg/probes/types.go
package probes

import (
    "encoding/json"
    "net/url"
    "time"
)

// Target represents a discovery target.
type Target struct {
    URL        *url.URL
    Host       string
    Port       int
    Scheme     string
    BasePath   string
    AuthHeader string
}

// ProbeOptions configures probe execution.
type ProbeOptions struct {
    Timeout      time.Duration
    MaxDepth     int
    Concurrency  int
    RateLimit    float64
    UserAgent    string
    Headers      map[string]string
    Scope        ScopeType
}

// ScopeType defines URL scope for crawling.
type ScopeType int

const (
    ScopeSameHost   ScopeType = iota // Same host only
    ScopeSameDomain                   // Same domain (includes subdomains)
    ScopeCustom                       // Custom regex
)

// ProbeResult contains probe execution results.
type ProbeResult struct {
    ProbeName    string        `json:"probe_name"`
    Endpoints    []APIEndpoint `json:"endpoints"`
    SpecsFound   []string      `json:"specs_found,omitempty"`
    Errors       []ProbeError  `json:"errors,omitempty"`
    Duration     time.Duration `json:"duration"`
}

// APIEndpoint represents a discovered API endpoint.
type APIEndpoint struct {
    URL          string            `json:"url"`
    Path         string            `json:"path"`
    Method       string            `json:"method"`
    Source       string            `json:"source"`
    SourceFile   string            `json:"source_file,omitempty"`
    Confidence   string            `json:"confidence"`
    Protocol     string            `json:"protocol"`
    Parameters   []Parameter       `json:"parameters,omitempty"`
    Headers      map[string]string `json:"headers,omitempty"`
    AuthRequired bool              `json:"auth_required"`
    AuthTypes    []string          `json:"auth_types,omitempty"`
    StatusCode   int               `json:"status_code,omitempty"`
    ContentType  string            `json:"content_type,omitempty"`
    OperationID  string            `json:"operation_id,omitempty"`
    Tags         []string          `json:"tags,omitempty"`
    Summary      string            `json:"summary,omitempty"`
    Deprecated   bool              `json:"deprecated,omitempty"`
    DiscoveredAt time.Time         `json:"discovered_at"`
    Raw          json.RawMessage   `json:"raw,omitempty"`
}

// Parameter represents an API parameter.
type Parameter struct {
    Name     string `json:"name"`
    In       string `json:"in"` // path, query, header, body
    Type     string `json:"type"`
    Required bool   `json:"required"`
    Example  string `json:"example,omitempty"`
}

// ProbeError records probe-specific errors.
type ProbeError struct {
    Probe   string `json:"probe"`
    Message string `json:"message"`
    URL     string `json:"url,omitempty"`
}
```

**Step 5: Write probe registry wrapper**

```go
// pkg/probes/registry.go
package probes

import (
    "github.com/praetorian-inc/vespasian/pkg/registry"
)

// Registry is the global probe registry.
var Registry = registry.New[Probe]("probes")

// Register adds a probe factory to the global registry.
func Register(name string, factory func(registry.Config) (Probe, error)) {
    Registry.Register(name, factory)
}

// List returns all registered probe names.
func List() []string {
    return Registry.List()
}

// Create instantiates a probe by name.
func Create(name string, cfg registry.Config) (Probe, error) {
    return Registry.Create(name, cfg)
}

// Has checks if a probe is registered.
func Has(name string) bool {
    return Registry.Has(name)
}
```

**Step 6: Run test to verify it passes**

Run: `go test ./pkg/probes/... -v`
Expected: PASS

**Step 7: Commit**

```bash
git add pkg/probes/
git commit -m "feat(probes): define probe interface hierarchy with registry"
```

---

### T004: Implement Configuration Loading

**Files:**
- Create: `pkg/config/config.go`
- Create: `pkg/config/validate.go`
- Create: `pkg/config/config_test.go`

**Step 1: Write failing test**

```go
// pkg/config/config_test.go
package config_test

import (
    "testing"

    "github.com/praetorian-inc/vespasian/pkg/config"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestConfig_LoadFromYAML(t *testing.T) {
    yaml := `
target: "https://api.example.com"
output:
  format: json
probes:
  enabled:
    - crawler
    - openapi
  crawler:
    depth: 3
rate_limit:
  requests_per_second: 10
`
    cfg, err := config.LoadFromBytes([]byte(yaml))
    require.NoError(t, err)
    assert.Equal(t, "https://api.example.com", cfg.Target)
    assert.Equal(t, "json", cfg.Output.Format)
    assert.Contains(t, cfg.Probes.Enabled, "crawler")
    assert.Equal(t, 3, cfg.Probes.Crawler.Depth)
    assert.Equal(t, float64(10), cfg.RateLimit.RequestsPerSecond)
}

func TestConfig_Validate_MissingTarget(t *testing.T) {
    cfg := &config.Config{}
    err := cfg.Validate()
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "target")
}

func TestConfig_Defaults(t *testing.T) {
    cfg := config.NewWithDefaults()
    assert.Equal(t, 2, cfg.Probes.Crawler.Depth)
    assert.Equal(t, float64(10), cfg.RateLimit.RequestsPerSecond)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/config/... -v`
Expected: FAIL

**Step 3: Write config implementation**

```go
// pkg/config/config.go
package config

import (
    "fmt"
    "os"

    "gopkg.in/yaml.v3"
)

// Config is the main configuration structure.
type Config struct {
    Target    string       `yaml:"target"`
    Output    OutputConfig `yaml:"output"`
    Probes    ProbesConfig `yaml:"probes"`
    RateLimit RateLimitConfig `yaml:"rate_limit"`
    Auth      AuthConfig   `yaml:"auth"`
}

// OutputConfig configures output format.
type OutputConfig struct {
    Format string `yaml:"format"` // json, csv, nuclei
    File   string `yaml:"file"`
}

// ProbesConfig configures probe behavior.
type ProbesConfig struct {
    Enabled   []string       `yaml:"enabled"`
    Crawler   CrawlerConfig  `yaml:"crawler"`
    OpenAPI   OpenAPIConfig  `yaml:"openapi"`
    GraphQL   GraphQLConfig  `yaml:"graphql"`
    GRPC      GRPCConfig     `yaml:"grpc"`
    WebSocket WebSocketConfig `yaml:"websocket"`
    WSDL      WSDLConfig     `yaml:"wsdl"`
}

// CrawlerConfig configures the HTTP crawler.
type CrawlerConfig struct {
    Depth       int    `yaml:"depth"`
    Concurrent  int    `yaml:"concurrent"`
    Scope       string `yaml:"scope"`
}

// OpenAPIConfig configures OpenAPI detection.
type OpenAPIConfig struct {
    Locations []string `yaml:"locations"`
    Versions  []string `yaml:"versions"`
}

// GraphQLConfig configures GraphQL detection.
type GraphQLConfig struct {
    Introspection bool     `yaml:"introspection"`
    CommonPaths   []string `yaml:"common_paths"`
}

// GRPCConfig configures gRPC detection.
type GRPCConfig struct {
    Reflection bool  `yaml:"reflection"`
    Ports      []int `yaml:"ports"`
}

// WebSocketConfig configures WebSocket detection.
type WebSocketConfig struct {
    CommonPaths []string `yaml:"common_paths"`
}

// WSDLConfig configures WSDL/SOAP detection.
type WSDLConfig struct {
    Locations []string `yaml:"locations"`
}

// RateLimitConfig configures rate limiting.
type RateLimitConfig struct {
    RequestsPerSecond float64 `yaml:"requests_per_second"`
    Burst             int     `yaml:"burst"`
}

// AuthConfig configures authentication.
type AuthConfig struct {
    Type   string `yaml:"type"` // bearer, basic, apikey
    Token  string `yaml:"token"`
    Header string `yaml:"header"`
}

// LoadFromFile loads configuration from a YAML file.
func LoadFromFile(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file: %w", err)
    }
    return LoadFromBytes(data)
}

// LoadFromBytes loads configuration from YAML bytes.
func LoadFromBytes(data []byte) (*Config, error) {
    cfg := NewWithDefaults()
    if err := yaml.Unmarshal(data, cfg); err != nil {
        return nil, fmt.Errorf("failed to parse config: %w", err)
    }
    return cfg, nil
}

// NewWithDefaults creates a Config with default values.
func NewWithDefaults() *Config {
    return &Config{
        Output: OutputConfig{
            Format: "json",
        },
        Probes: ProbesConfig{
            Enabled: []string{"crawler", "openapi", "graphql"},
            Crawler: CrawlerConfig{
                Depth:      2,
                Concurrent: 10,
                Scope:      "same-host",
            },
            OpenAPI: OpenAPIConfig{
                Locations: []string{"/openapi.json", "/swagger.json", "/api-docs"},
                Versions:  []string{"2.0", "3.0", "3.1"},
            },
            GraphQL: GraphQLConfig{
                Introspection: true,
                CommonPaths:   []string{"/graphql", "/api/graphql"},
            },
            GRPC: GRPCConfig{
                Reflection: true,
                Ports:      []int{50051, 9090},
            },
        },
        RateLimit: RateLimitConfig{
            RequestsPerSecond: 10,
            Burst:             20,
        },
    }
}
```

**Step 4: Write validation**

```go
// pkg/config/validate.go
package config

import (
    "fmt"
    "net/url"
)

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
    if c.Target == "" {
        return fmt.Errorf("target is required")
    }

    if _, err := url.Parse(c.Target); err != nil {
        return fmt.Errorf("invalid target URL: %w", err)
    }

    if c.RateLimit.RequestsPerSecond <= 0 {
        return fmt.Errorf("rate_limit.requests_per_second must be positive")
    }

    validFormats := map[string]bool{"json": true, "csv": true, "nuclei": true}
    if c.Output.Format != "" && !validFormats[c.Output.Format] {
        return fmt.Errorf("invalid output format: %s (valid: json, csv, nuclei)", c.Output.Format)
    }

    return nil
}
```

**Step 5: Run test to verify it passes**

Run: `go test ./pkg/config/... -v`
Expected: PASS

**Step 6: Commit**

```bash
git add pkg/config/
git commit -m "feat(config): implement YAML configuration loading and validation"
```

---

### T005: Implement CLI Entrypoint

**Files:**
- Create: `cmd/vespasian/main.go`
- Create: `cmd/vespasian/scan.go`
- Create: `cmd/vespasian/version.go`

**Step 1: Write main entrypoint**

```go
// cmd/vespasian/main.go
package main

import (
    "fmt"
    "os"

    "github.com/alecthomas/kong"
)

var version = "dev"

// CLI defines the command-line interface.
type CLI struct {
    Scan    ScanCmd    `cmd:"" help:"Scan a target for API endpoints."`
    List    ListCmd    `cmd:"" help:"List available probes."`
    Version VersionCmd `cmd:"" help:"Print version information."`
}

func main() {
    cli := &CLI{}
    ctx := kong.Parse(cli,
        kong.Name("vespasian"),
        kong.Description("Comprehensive API surface enumeration tool"),
        kong.UsageOnError(),
    )

    err := ctx.Run()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
}
```

**Step 2: Write scan command**

```go
// cmd/vespasian/scan.go
package main

import (
    "fmt"

    "github.com/praetorian-inc/vespasian/pkg/config"
    "github.com/praetorian-inc/vespasian/pkg/probes"
)

// ScanCmd implements the scan command.
type ScanCmd struct {
    Target  string `arg:"" required:"" help:"Target URL to scan."`
    Config  string `short:"c" help:"Path to configuration file."`
    Output  string `short:"o" help:"Output file path."`
    Format  string `short:"f" default:"json" help:"Output format (json, csv, nuclei)."`
    Depth   int    `short:"d" default:"2" help:"Crawl depth."`
    Rate    float64 `short:"r" default:"10" help:"Requests per second."`
    Probes  []string `short:"p" help:"Probes to enable (comma-separated)."`
    Verbose bool    `short:"v" help:"Verbose output."`
}

// Run executes the scan command.
func (c *ScanCmd) Run() error {
    // Load configuration
    var cfg *config.Config
    var err error

    if c.Config != "" {
        cfg, err = config.LoadFromFile(c.Config)
        if err != nil {
            return fmt.Errorf("failed to load config: %w", err)
        }
    } else {
        cfg = config.NewWithDefaults()
    }

    // Override with CLI flags
    cfg.Target = c.Target
    if c.Output != "" {
        cfg.Output.File = c.Output
    }
    if c.Format != "" {
        cfg.Output.Format = c.Format
    }
    if c.Depth > 0 {
        cfg.Probes.Crawler.Depth = c.Depth
    }
    if c.Rate > 0 {
        cfg.RateLimit.RequestsPerSecond = c.Rate
    }
    if len(c.Probes) > 0 {
        cfg.Probes.Enabled = c.Probes
    }

    // Validate configuration
    if err := cfg.Validate(); err != nil {
        return fmt.Errorf("invalid configuration: %w", err)
    }

    // List available probes
    fmt.Printf("Available probes: %v\n", probes.List())
    fmt.Printf("Target: %s\n", cfg.Target)
    fmt.Printf("Enabled probes: %v\n", cfg.Probes.Enabled)

    // TODO: Implement actual scanning in Batch 2
    fmt.Println("Scanning... (not yet implemented)")

    return nil
}

// ListCmd implements the list command.
type ListCmd struct{}

// Run lists available probes.
func (c *ListCmd) Run() error {
    fmt.Println("Available probes:")
    for _, name := range probes.List() {
        fmt.Printf("  - %s\n", name)
    }
    return nil
}
```

**Step 3: Write version command**

```go
// cmd/vespasian/version.go
package main

import "fmt"

// VersionCmd prints version information.
type VersionCmd struct{}

// Run prints the version.
func (c *VersionCmd) Run() error {
    fmt.Printf("vespasian version %s\n", version)
    return nil
}
```

**Step 4: Build and verify**

Run: `go build ./cmd/vespasian`
Expected: Exit code 0, binary created

Run: `./vespasian --help`
Expected: Usage information displayed

Run: `./vespasian version`
Expected: "vespasian version dev"

**Step 5: Commit**

```bash
git add cmd/vespasian/
git commit -m "feat(cli): implement Kong-based CLI with scan and list commands"
```

---

## Batch 2: HTTP Crawler

**Exit Criteria:**
- [ ] 6 files created in pkg/crawler/, pkg/http/
- [ ] Crawler probe registered and discoverable via `vespasian list`
- [ ] Unit tests pass: `go test ./pkg/crawler/... ./pkg/http/... -v`
- [ ] Integration test with httptest server passes

### T006: Implement HTTP Client with Rate Limiting

**Files:**
- Create: `pkg/http/client.go`
- Create: `pkg/http/ratelimit.go`
- Create: `pkg/http/client_test.go`

**Step 1: Write failing test**

```go
// pkg/http/client_test.go
package http_test

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    vhttp "github.com/praetorian-inc/vespasian/pkg/http"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestClient_Get(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"status":"ok"}`))
    }))
    defer server.Close()

    client := vhttp.NewClient(vhttp.ClientOptions{
        Timeout:           5 * time.Second,
        RateLimit:         10,
        UserAgent:         "vespasian/test",
    })

    resp, err := client.Get(context.Background(), server.URL)
    require.NoError(t, err)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestClient_RateLimiting(t *testing.T) {
    requestCount := 0
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        requestCount++
        w.WriteHeader(http.StatusOK)
    }))
    defer server.Close()

    client := vhttp.NewClient(vhttp.ClientOptions{
        Timeout:   5 * time.Second,
        RateLimit: 5, // 5 requests per second
    })

    start := time.Now()
    for i := 0; i < 10; i++ {
        _, err := client.Get(context.Background(), server.URL)
        require.NoError(t, err)
    }
    elapsed := time.Since(start)

    // 10 requests at 5/sec should take at least 1.5 seconds
    assert.GreaterOrEqual(t, elapsed, 1500*time.Millisecond)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/http/... -v`
Expected: FAIL

**Step 3: Write rate limiter**

```go
// pkg/http/ratelimit.go
package http

import (
    "context"

    "golang.org/x/time/rate"
)

// RateLimiter wraps a token bucket rate limiter.
type RateLimiter struct {
    limiter *rate.Limiter
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
    return &RateLimiter{
        limiter: rate.NewLimiter(rate.Limit(rps), burst),
    }
}

// Wait blocks until a token is available or context is cancelled.
func (r *RateLimiter) Wait(ctx context.Context) error {
    return r.limiter.Wait(ctx)
}

// Allow checks if a request can proceed without blocking.
func (r *RateLimiter) Allow() bool {
    return r.limiter.Allow()
}
```

**Step 4: Write HTTP client**

```go
// pkg/http/client.go
package http

import (
    "context"
    "io"
    "net/http"
    "time"
)

// ClientOptions configures the HTTP client.
type ClientOptions struct {
    Timeout   time.Duration
    RateLimit float64
    Burst     int
    UserAgent string
    Headers   map[string]string
}

// Client wraps http.Client with rate limiting.
type Client struct {
    client    *http.Client
    limiter   *RateLimiter
    userAgent string
    headers   map[string]string
}

// NewClient creates a new rate-limited HTTP client.
func NewClient(opts ClientOptions) *Client {
    if opts.Timeout == 0 {
        opts.Timeout = 10 * time.Second
    }
    if opts.RateLimit == 0 {
        opts.RateLimit = 10
    }
    if opts.Burst == 0 {
        opts.Burst = int(opts.RateLimit * 2)
    }
    if opts.UserAgent == "" {
        opts.UserAgent = "vespasian/1.0"
    }

    return &Client{
        client: &http.Client{
            Timeout: opts.Timeout,
            Transport: &http.Transport{
                MaxIdleConns:        100,
                MaxIdleConnsPerHost: 10,
                IdleConnTimeout:     90 * time.Second,
            },
        },
        limiter:   NewRateLimiter(opts.RateLimit, opts.Burst),
        userAgent: opts.UserAgent,
        headers:   opts.Headers,
    }
}

// Get performs a rate-limited GET request.
func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
    if err := c.limiter.Wait(ctx); err != nil {
        return nil, err
    }

    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return nil, err
    }

    c.setHeaders(req)
    return c.client.Do(req)
}

// Do performs a rate-limited HTTP request.
func (c *Client) Do(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
    if err := c.limiter.Wait(ctx); err != nil {
        return nil, err
    }

    req, err := http.NewRequestWithContext(ctx, method, url, body)
    if err != nil {
        return nil, err
    }

    c.setHeaders(req)
    return c.client.Do(req)
}

func (c *Client) setHeaders(req *http.Request) {
    req.Header.Set("User-Agent", c.userAgent)
    for k, v := range c.headers {
        req.Header.Set(k, v)
    }
}
```

**Step 5: Add rate package dependency**

```bash
go get golang.org/x/time@latest
```

**Step 6: Run test to verify it passes**

Run: `go test ./pkg/http/... -v`
Expected: PASS

**Step 7: Commit**

```bash
git add pkg/http/
git commit -m "feat(http): implement rate-limited HTTP client"
```

---

### T007: Implement HTML/Link Parser

**Files:**
- Create: `pkg/crawler/parser.go`
- Create: `pkg/crawler/parser_test.go`

**Step 1: Write failing test**

```go
// pkg/crawler/parser_test.go
package crawler_test

import (
    "testing"

    "github.com/praetorian-inc/vespasian/pkg/crawler"
    "github.com/stretchr/testify/assert"
)

func TestParser_ExtractLinks(t *testing.T) {
    html := `
<!DOCTYPE html>
<html>
<head>
    <script src="/js/app.js"></script>
    <link href="/css/style.css">
</head>
<body>
    <a href="/page1">Page 1</a>
    <a href="/page2">Page 2</a>
    <a href="https://external.com/path">External</a>
    <form action="/api/submit" method="POST"></form>
    <img src="/images/logo.png">
</body>
</html>`

    parser := crawler.NewParser("https://example.com")
    links, err := parser.ExtractLinks([]byte(html))
    assert.NoError(t, err)

    // Should find: /page1, /page2, /api/submit, /js/app.js
    assert.Contains(t, links, "https://example.com/page1")
    assert.Contains(t, links, "https://example.com/page2")
    assert.Contains(t, links, "https://example.com/api/submit")
    assert.Contains(t, links, "https://example.com/js/app.js")
}

func TestParser_ExtractAPIEndpoints(t *testing.T) {
    html := `
<a href="/api/users">Users API</a>
<a href="/api/v1/products">Products</a>
<a href="/graphql">GraphQL</a>
<a href="/swagger.json">Swagger</a>
`
    parser := crawler.NewParser("https://api.example.com")
    endpoints := parser.ExtractAPIEndpoints([]byte(html))

    assert.Contains(t, endpoints, "https://api.example.com/api/users")
    assert.Contains(t, endpoints, "https://api.example.com/api/v1/products")
    assert.Contains(t, endpoints, "https://api.example.com/graphql")
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/crawler/... -v`
Expected: FAIL

**Step 3: Write parser implementation**

```go
// pkg/crawler/parser.go
package crawler

import (
    "bytes"
    "net/url"
    "regexp"
    "strings"

    "golang.org/x/net/html"
)

// Parser extracts links and API endpoints from HTML.
type Parser struct {
    baseURL *url.URL
}

// NewParser creates a new HTML parser.
func NewParser(baseURLStr string) *Parser {
    base, _ := url.Parse(baseURLStr)
    return &Parser{baseURL: base}
}

// ExtractLinks extracts all links from HTML content.
func (p *Parser) ExtractLinks(content []byte) ([]string, error) {
    doc, err := html.Parse(bytes.NewReader(content))
    if err != nil {
        return nil, err
    }

    links := make(map[string]bool)
    p.extractFromNode(doc, links)

    result := make([]string, 0, len(links))
    for link := range links {
        result = append(result, link)
    }
    return result, nil
}

func (p *Parser) extractFromNode(n *html.Node, links map[string]bool) {
    if n.Type == html.ElementNode {
        var attrName string
        switch n.Data {
        case "a":
            attrName = "href"
        case "form":
            attrName = "action"
        case "script":
            attrName = "src"
        case "link":
            attrName = "href"
        case "img":
            attrName = "src"
        case "iframe":
            attrName = "src"
        }

        if attrName != "" {
            for _, attr := range n.Attr {
                if attr.Key == attrName {
                    if resolved := p.resolveURL(attr.Val); resolved != "" {
                        links[resolved] = true
                    }
                }
            }
        }
    }

    for c := n.FirstChild; c != nil; c = c.NextSibling {
        p.extractFromNode(c, links)
    }
}

func (p *Parser) resolveURL(href string) string {
    if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
        return ""
    }

    ref, err := url.Parse(href)
    if err != nil {
        return ""
    }

    resolved := p.baseURL.ResolveReference(ref)
    return resolved.String()
}

// ExtractAPIEndpoints extracts likely API endpoint URLs.
func (p *Parser) ExtractAPIEndpoints(content []byte) []string {
    links, _ := p.ExtractLinks(content)

    apiPatterns := []*regexp.Regexp{
        regexp.MustCompile(`/api/`),
        regexp.MustCompile(`/v\d+/`),
        regexp.MustCompile(`/graphql`),
        regexp.MustCompile(`/rest/`),
        regexp.MustCompile(`\.json$`),
        regexp.MustCompile(`\.yaml$`),
        regexp.MustCompile(`/swagger`),
        regexp.MustCompile(`/openapi`),
    }

    var endpoints []string
    for _, link := range links {
        for _, pattern := range apiPatterns {
            if pattern.MatchString(link) {
                endpoints = append(endpoints, link)
                break
            }
        }
    }

    return endpoints
}
```

**Step 4: Add html package dependency**

```bash
go get golang.org/x/net/html@latest
```

**Step 5: Run test to verify it passes**

Run: `go test ./pkg/crawler/... -v`
Expected: PASS

**Step 6: Commit**

```bash
git add pkg/crawler/
git commit -m "feat(crawler): implement HTML link and API endpoint parser"
```

---

### T008: Implement Crawler Probe

**Files:**
- Create: `pkg/crawler/crawler.go`
- Create: `pkg/crawler/scope.go`
- Create: `pkg/crawler/probe.go`
- Modify: `cmd/vespasian/main.go` (import probe package)

**Step 1: Write failing test**

```go
// pkg/crawler/crawler_test.go (add to existing)

func TestCrawlerProbe_Run(t *testing.T) {
    // Create test server with multiple pages
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte(`<html><a href="/api/users">Users</a><a href="/page2">Page 2</a></html>`))
    })
    mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte(`<html><a href="/api/products">Products</a></html>`))
    })
    mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"users":[]}`))
    })
    mux.HandleFunc("/api/products", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"products":[]}`))
    })

    server := httptest.NewServer(mux)
    defer server.Close()

    probe, err := crawler.NewProbe(nil)
    require.NoError(t, err)

    target := probes.Target{URL: mustParseURL(server.URL)}
    result, err := probe.Run(context.Background(), target, probes.ProbeOptions{
        MaxDepth:    2,
        Concurrency: 5,
        RateLimit:   100,
    })
    require.NoError(t, err)

    // Should discover /api/users and /api/products
    urls := extractURLs(result.Endpoints)
    assert.Contains(t, urls, server.URL+"/api/users")
    assert.Contains(t, urls, server.URL+"/api/products")
}
```

**Step 2-6: Implementation details omitted for brevity - follow TDD pattern**

**Exit criteria for T008:**
- Crawler probe registered via init()
- Discoverable via `vespasian list`
- Crawls pages up to configured depth
- Extracts API endpoints

---

## Batch 3: JavaScript Parsing (Headless Browser)

**Exit Criteria:**
- [ ] 4 files created in pkg/js/, internal/browser/
- [ ] JS parser extracts XHR/fetch endpoints from JavaScript
- [ ] Optional ChromeDP integration for dynamic JS execution
- [ ] Unit tests pass with sample JS fixtures

### T009: Implement Static JS Parser

### T010: Implement XHR/Fetch Endpoint Extraction

### T011: Implement Headless Browser Integration (Optional)

*Tasks T009-T011 follow same TDD pattern - details omitted for brevity*

---

## Batch 4: API Specification Probes

**Exit Criteria:**
- [ ] 8 files created in pkg/spec/openapi/, pkg/spec/graphql/
- [ ] OpenAPI probe parses v2.0, v3.0, v3.1 specs
- [ ] GraphQL probe performs introspection queries
- [ ] Both probes registered and discoverable
- [ ] Unit tests pass with spec fixtures in testdata/

### T012: Implement OpenAPI Parser

**Files:**
- Create: `pkg/spec/openapi/parser.go`
- Create: `pkg/spec/openapi/parser_test.go`
- Create: `testdata/openapi/petstore-v3.json`

### T013: Implement OpenAPI Probe

**Files:**
- Create: `pkg/spec/openapi/probe.go`
- Create: `pkg/spec/openapi/probe_test.go`

### T014: Implement GraphQL Introspection

**Files:**
- Create: `pkg/spec/graphql/introspection.go`
- Create: `pkg/spec/graphql/introspection_test.go`

### T015: Implement GraphQL Probe

**Files:**
- Create: `pkg/spec/graphql/probe.go`
- Create: `pkg/spec/graphql/probe_test.go`
- Create: `testdata/graphql/schema.json`

*Tasks T012-T015 follow same TDD pattern*

---

## Batch 5: Protocol Probes (gRPC, WebSocket, WSDL)

**Exit Criteria:**
- [ ] 10 files created in pkg/protocols/, pkg/spec/wsdl/
- [ ] gRPC probe performs reflection queries
- [ ] WebSocket probe detects WS endpoints
- [ ] WSDL probe parses SOAP services
- [ ] All probes registered and discoverable
- [ ] Unit tests pass

### T016: Implement gRPC Reflection Client

**Files:**
- Create: `pkg/protocols/grpc/reflection.go`
- Create: `pkg/protocols/grpc/reflection_test.go`

### T017: Implement gRPC Probe

**Files:**
- Create: `pkg/protocols/grpc/probe.go`
- Create: `pkg/protocols/grpc/probe_test.go`

### T018: Implement WebSocket Client

**Files:**
- Create: `pkg/protocols/websocket/client.go`
- Create: `pkg/protocols/websocket/client_test.go`

### T019: Implement WebSocket Probe

**Files:**
- Create: `pkg/protocols/websocket/probe.go`
- Create: `pkg/protocols/websocket/probe_test.go`

### T020: Implement WSDL Parser

**Files:**
- Create: `pkg/spec/wsdl/parser.go`
- Create: `pkg/spec/wsdl/parser_test.go`
- Create: `testdata/wsdl/sample.wsdl`

### T021: Implement WSDL Probe

**Files:**
- Create: `pkg/spec/wsdl/probe.go`
- Create: `pkg/spec/wsdl/probe_test.go`

*Tasks T016-T021 follow same TDD pattern*

---

## Batch 6: Output and Integration (REVISED - SDK Integration)

> **Architecture Decision (2026-01-28):** Hybrid adapter approach approved by capability-lead and backend-lead.
> Integrates with `capability-sdk` for output formatting instead of custom implementations.
> See `.capability-development/agents/capability-lead-architecture-review.md` for full analysis.

**Exit Criteria:**
- [ ] 6 files created in pkg/output/, pkg/discovery/
- [ ] Adapter converts ProbeResult → capability.Finding
- [ ] 5 output formats working (Terminal, JSON, NDJSON, Markdown, SARIF)
- [ ] End-to-end scan produces valid output
- [ ] All tests pass: `go test ./... -v`
- [ ] Existing 112 tests remain unchanged and passing

### T022: Implement SDK Adapter Layer

**Files:**
- Create: `pkg/output/adapter.go`
- Create: `pkg/output/adapter_test.go`

**Step 1: Add capability-sdk dependency**

```bash
cd /Users/nathansportsman/capabilities/modules/vespasian
go get github.com/praetorian-inc/capability-sdk@latest
```

**Step 2: Write failing test**

```go
// pkg/output/adapter_test.go
package output_test

import (
    "testing"

    "github.com/praetorian-inc/capability-sdk/pkg/capability"
    "github.com/praetorian-inc/vespasian/pkg/output"
    "github.com/praetorian-inc/vespasian/pkg/probes"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestToFindings_SingleEndpoint(t *testing.T) {
    results := []probes.ProbeResult{
        {
            ProbeCategory: probes.CategoryHTTP,
            Success:       true,
            Endpoints: []probes.APIEndpoint{
                {Path: "/api/users", Method: "GET"},
            },
        },
    }

    findings := output.ToFindings(results)

    require.Len(t, findings, 1)
    assert.Equal(t, capability.FindingAsset, findings[0].Type)
    assert.Equal(t, "/api/users", findings[0].Data["path"])
    assert.Equal(t, "GET", findings[0].Data["method"])
}

func TestToFindings_MultipleEndpoints(t *testing.T) {
    results := []probes.ProbeResult{
        {
            ProbeCategory: probes.CategoryHTTP,
            Success:       true,
            Endpoints: []probes.APIEndpoint{
                {Path: "/api/users", Method: "GET"},
                {Path: "/api/users", Method: "POST"},
            },
        },
        {
            ProbeCategory: probes.CategoryProtocol,
            Success:       true,
            Endpoints: []probes.APIEndpoint{
                {Path: "/graphql", Method: "POST"},
            },
        },
    }

    findings := output.ToFindings(results)
    assert.Len(t, findings, 3)
}

func TestToFindings_ProbeError(t *testing.T) {
    results := []probes.ProbeResult{
        {
            ProbeCategory: probes.CategoryHTTP,
            Success:       false,
            Error:         fmt.Errorf("connection refused"),
        },
    }

    findings := output.ToFindings(results)

    require.Len(t, findings, 1)
    assert.Equal(t, "probe_error", findings[0].Data["type"])
    assert.Contains(t, findings[0].Data["error"], "connection refused")
}
```

**Step 3: Run test to verify it fails**

Run: `go test ./pkg/output/... -v`
Expected: FAIL (package doesn't exist)

**Step 4: Write implementation**

```go
// pkg/output/adapter.go
package output

import (
    "github.com/praetorian-inc/capability-sdk/pkg/capability"
    "github.com/praetorian-inc/vespasian/pkg/probes"
)

// ToFindings converts vespasian's internal ProbeResult to SDK Finding type
// for output formatting while preserving domain-specific metadata.
func ToFindings(results []probes.ProbeResult) []capability.Finding {
    var findings []capability.Finding

    for _, pr := range results {
        // Convert each discovered endpoint to a Finding
        for _, ep := range pr.Endpoints {
            f := capability.Finding{
                Type:     capability.FindingAsset,
                Severity: capability.SeverityInfo,
                Data: map[string]any{
                    "path":           ep.Path,
                    "method":         ep.Method,
                    "probe_category": pr.ProbeCategory.String(),
                    "source":         "vespasian",
                },
            }
            findings = append(findings, f)
        }

        // If probe had error, create error finding
        if pr.Error != nil && !pr.Success {
            f := capability.Finding{
                Type:     capability.FindingAttribute,
                Severity: capability.SeverityInfo,
                Data: map[string]any{
                    "type":           "probe_error",
                    "probe_category": pr.ProbeCategory.String(),
                    "error":          pr.Error.Error(),
                },
            }
            findings = append(findings, f)
        }
    }

    return findings
}

// ToTarget converts vespasian's Target to SDK Target type.
func ToTarget(target probes.Target) capability.Target {
    return capability.Target{
        Type:  capability.TargetURL,
        Value: fmt.Sprintf("%s:%d", target.Host, target.Port),
        Meta:  map[string]string{},
    }
}
```

**Step 5: Run test to verify it passes**

Run: `go test ./pkg/output/... -v`
Expected: PASS

**Step 6: Commit**

```bash
git add pkg/output/
git commit -m "feat(output): add SDK adapter for ProbeResult to Finding conversion"
```

---

### T023: Implement CLI Output Routing

**Files:**
- Create: `pkg/output/writer.go`
- Create: `pkg/output/writer_test.go`
- Modify: `cmd/vespasian/scan.go` (add --format flag)

**Step 1: Write failing test**

```go
// pkg/output/writer_test.go
package output_test

import (
    "bytes"
    "testing"

    "github.com/praetorian-inc/capability-sdk/pkg/capability"
    "github.com/praetorian-inc/vespasian/pkg/output"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestWriter_JSON(t *testing.T) {
    var buf bytes.Buffer
    w, err := output.NewWriter("json", &buf)
    require.NoError(t, err)

    findings := []capability.Finding{
        {Type: capability.FindingAsset, Data: map[string]any{"path": "/api"}},
    }

    err = w.Write(findings)
    require.NoError(t, err)

    assert.Contains(t, buf.String(), `"path":"/api"`)
}

func TestWriter_Terminal(t *testing.T) {
    var buf bytes.Buffer
    w, err := output.NewWriter("terminal", &buf)
    require.NoError(t, err)

    findings := []capability.Finding{
        {Type: capability.FindingAsset, Data: map[string]any{"path": "/api"}},
    }

    err = w.Write(findings)
    require.NoError(t, err)

    assert.NotEmpty(t, buf.String())
}

func TestWriter_InvalidFormat(t *testing.T) {
    var buf bytes.Buffer
    _, err := output.NewWriter("invalid", &buf)
    assert.Error(t, err)
}
```

**Step 2: Write implementation**

```go
// pkg/output/writer.go
package output

import (
    "context"
    "fmt"
    "io"

    "github.com/praetorian-inc/capability-sdk/pkg/capability"
    "github.com/praetorian-inc/capability-sdk/pkg/formatter"
)

// Writer wraps SDK formatters for vespasian output.
type Writer struct {
    formatter formatter.Formatter
}

// NewWriter creates a new output writer for the given format.
// Supported formats: terminal, json, ndjson, markdown, sarif
func NewWriter(format string, w io.Writer) (*Writer, error) {
    var cfg formatter.Config
    cfg.Writer = w

    switch format {
    case "terminal", "":
        cfg.Format = formatter.FormatTerminal
        cfg.Colored = true
    case "json":
        cfg.Format = formatter.FormatJSON
        cfg.Pretty = true
    case "ndjson":
        cfg.Format = formatter.FormatNDJSON
    case "markdown", "md":
        cfg.Format = formatter.FormatMarkdown
    case "sarif":
        cfg.Format = formatter.FormatSARIF
        cfg.ToolInfo = formatter.ToolInfo{
            Name:        "vespasian",
            Version:     "1.0.0",
            Description: "API surface enumeration tool",
        }
    default:
        return nil, fmt.Errorf("unsupported output format: %s (valid: terminal, json, ndjson, markdown, sarif)", format)
    }

    f, err := formatter.New(cfg)
    if err != nil {
        return nil, fmt.Errorf("failed to create formatter: %w", err)
    }

    return &Writer{formatter: f}, nil
}

// Write outputs the findings using the configured formatter.
func (w *Writer) Write(findings []capability.Finding) error {
    ctx := context.Background()

    if err := w.formatter.Initialize(ctx, formatter.ToolInfo{Name: "vespasian"}); err != nil {
        return err
    }

    for _, f := range findings {
        ff := formatter.FromCapabilityFinding(f)
        if err := w.formatter.Format(ctx, ff); err != nil {
            return err
        }
    }

    summary := formatter.Summary{TotalFindings: len(findings)}
    if err := w.formatter.Complete(ctx, summary); err != nil {
        return err
    }

    return w.formatter.Close()
}

// SupportedFormats returns the list of supported output formats.
func SupportedFormats() []string {
    return []string{"terminal", "json", "ndjson", "markdown", "sarif"}
}
```

**Step 3: Update CLI scan command**

Modify `cmd/vespasian/scan.go` to add `--format` flag and wire up output writer.

**Step 4: Commit**

```bash
git add pkg/output/ cmd/vespasian/
git commit -m "feat(output): add CLI output routing with SDK formatters"
```

---

### T024: Implement Discovery Orchestrator

**Files:**
- Create: `pkg/discovery/orchestrator.go`
- Create: `pkg/discovery/orchestrator_test.go`
- Create: `pkg/discovery/dedupe.go`
- Modify: `cmd/vespasian/scan.go` (wire up orchestrator)

**Step 1: Write failing test**

```go
// pkg/discovery/orchestrator_test.go
package discovery_test

import (
    "context"
    "testing"

    "github.com/praetorian-inc/vespasian/pkg/discovery"
    "github.com/praetorian-inc/vespasian/pkg/probes"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

type mockProbe struct {
    name      string
    endpoints []probes.APIEndpoint
}

func (m *mockProbe) Name() string                               { return m.name }
func (m *mockProbe) Category() probes.ProbeCategory             { return probes.CategoryHTTP }
func (m *mockProbe) Priority() int                              { return 100 }
func (m *mockProbe) Accepts(target probes.Target) bool          { return true }
func (m *mockProbe) Run(ctx context.Context, target probes.Target, opts probes.ProbeOptions) (*probes.ProbeResult, error) {
    return &probes.ProbeResult{
        ProbeCategory: probes.CategoryHTTP,
        Success:       true,
        Endpoints:     m.endpoints,
    }, nil
}

func TestOrchestrator_RunProbes(t *testing.T) {
    probeList := []probes.Probe{
        &mockProbe{name: "crawler", endpoints: []probes.APIEndpoint{{Path: "/api/users", Method: "GET"}}},
        &mockProbe{name: "openapi", endpoints: []probes.APIEndpoint{{Path: "/api/products", Method: "POST"}}},
    }

    orch := discovery.NewOrchestrator(probeList)
    target := probes.Target{Host: "example.com", Port: 443}

    results, err := orch.Run(context.Background(), target)
    require.NoError(t, err)
    assert.Len(t, results, 2)
}

func TestOrchestrator_Dedupe(t *testing.T) {
    probeList := []probes.Probe{
        &mockProbe{name: "crawler", endpoints: []probes.APIEndpoint{{Path: "/api/users", Method: "GET"}}},
        &mockProbe{name: "openapi", endpoints: []probes.APIEndpoint{{Path: "/api/users", Method: "GET"}}}, // Duplicate
    }

    orch := discovery.NewOrchestrator(probeList)
    target := probes.Target{Host: "example.com", Port: 443}

    results, err := orch.Run(context.Background(), target)
    require.NoError(t, err)

    // After deduplication, should have 1 unique endpoint
    allEndpoints := discovery.DedupeEndpoints(results)
    assert.Len(t, allEndpoints, 1)
}
```

**Step 2: Write implementation**

```go
// pkg/discovery/orchestrator.go
package discovery

import (
    "context"
    "sort"
    "sync"

    "github.com/praetorian-inc/vespasian/pkg/probes"
)

// Orchestrator coordinates probe execution against targets.
type Orchestrator struct {
    probes []probes.Probe
}

// NewOrchestrator creates a new orchestrator with the given probes.
func NewOrchestrator(probeList []probes.Probe) *Orchestrator {
    // Sort by priority (higher priority first)
    sorted := make([]probes.Probe, len(probeList))
    copy(sorted, probeList)
    sort.Slice(sorted, func(i, j int) bool {
        return sorted[i].Priority() > sorted[j].Priority()
    })

    return &Orchestrator{probes: sorted}
}

// Run executes all applicable probes against the target.
func (o *Orchestrator) Run(ctx context.Context, target probes.Target) ([]probes.ProbeResult, error) {
    var (
        results []probes.ProbeResult
        mu      sync.Mutex
        wg      sync.WaitGroup
    )

    for _, p := range o.probes {
        if !p.Accepts(target) {
            continue
        }

        wg.Add(1)
        go func(probe probes.Probe) {
            defer wg.Done()

            result, err := probe.Run(ctx, target, probes.ProbeOptions{})
            if err != nil {
                result = &probes.ProbeResult{
                    ProbeCategory: probe.Category(),
                    Success:       false,
                    Error:         err,
                }
            }

            mu.Lock()
            results = append(results, *result)
            mu.Unlock()
        }(p)
    }

    wg.Wait()
    return results, nil
}
```

```go
// pkg/discovery/dedupe.go
package discovery

import "github.com/praetorian-inc/vespasian/pkg/probes"

// DedupeEndpoints removes duplicate endpoints across all probe results.
func DedupeEndpoints(results []probes.ProbeResult) []probes.APIEndpoint {
    seen := make(map[string]bool)
    var unique []probes.APIEndpoint

    for _, r := range results {
        for _, ep := range r.Endpoints {
            key := ep.Method + ":" + ep.Path
            if !seen[key] {
                seen[key] = true
                unique = append(unique, ep)
            }
        }
    }

    return unique
}
```

**Step 3: Commit**

```bash
git add pkg/discovery/
git commit -m "feat(discovery): implement probe orchestrator with deduplication"
```

---

### T025: End-to-End Integration Test

**Files:**
- Create: `tests/integration/scan_test.go`

**Step 1: Write integration test**

```go
// tests/integration/scan_test.go
package integration_test

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/praetorian-inc/vespasian/pkg/crawler"
    "github.com/praetorian-inc/vespasian/pkg/discovery"
    "github.com/praetorian-inc/vespasian/pkg/output"
    "github.com/praetorian-inc/vespasian/pkg/probes"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestEndToEnd_ScanAndOutput(t *testing.T) {
    // Setup test server
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte(`<html><a href="/api/users">Users</a></html>`))
    })
    mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"users":[]}`))
    })
    server := httptest.NewServer(mux)
    defer server.Close()

    // Create probes
    crawlerProbe, _ := crawler.NewProbe(nil)

    // Create orchestrator
    orch := discovery.NewOrchestrator([]probes.Probe{crawlerProbe})

    // Run scan
    target := probes.Target{Host: server.URL, Port: 80}
    results, err := orch.Run(context.Background(), target)
    require.NoError(t, err)

    // Convert to findings
    findings := output.ToFindings(results)
    assert.NotEmpty(t, findings)

    // Output as JSON
    var buf bytes.Buffer
    w, err := output.NewWriter("json", &buf)
    require.NoError(t, err)

    err = w.Write(findings)
    require.NoError(t, err)

    // Verify JSON output
    var outputData []map[string]any
    err = json.Unmarshal(buf.Bytes(), &outputData)
    require.NoError(t, err)
    assert.NotEmpty(t, outputData)
}

func TestEndToEnd_AllOutputFormats(t *testing.T) {
    findings := output.ToFindings([]probes.ProbeResult{
        {
            ProbeCategory: probes.CategoryHTTP,
            Success:       true,
            Endpoints:     []probes.APIEndpoint{{Path: "/api/test", Method: "GET"}},
        },
    })

    formats := []string{"terminal", "json", "ndjson", "markdown", "sarif"}

    for _, format := range formats {
        t.Run(format, func(t *testing.T) {
            var buf bytes.Buffer
            w, err := output.NewWriter(format, &buf)
            require.NoError(t, err)

            err = w.Write(findings)
            require.NoError(t, err)

            assert.NotEmpty(t, buf.String(), "output should not be empty for format: %s", format)
        })
    }
}
```

**Step 2: Run all tests**

Run: `go test ./... -v`
Expected: All 112+ tests pass

**Step 3: Commit**

```bash
git add tests/integration/
git commit -m "test(integration): add end-to-end scan and output tests"
```

---

## Task Dependencies

```
T001 (go.mod)
  └── T002 (registry)
        └── T003 (probes interface)
              ├── T004 (config)
              │     └── T005 (CLI)
              │           └── All batch 2-5 tasks
              │
              ├── T006-T008 (Batch 2: Crawler)
              ├── T009-T011 (Batch 3: JS Parser)
              ├── T012-T015 (Batch 4: Spec Probes)
              └── T016-T021 (Batch 5: Protocol Probes)
                    │
                    └── T022-T025 (Batch 6: Output & Integration)
```

---

## Summary

| Batch | Tasks | Files | Focus |
|-------|-------|-------|-------|
| 1 | T001-T005 | 9 | Core foundation (registry, interfaces, CLI) |
| 2 | T006-T008 | 6 | HTTP crawler probe |
| 3 | T009-T011 | 4 | JavaScript parsing |
| 4 | T012-T015 | 8 | OpenAPI, GraphQL probes |
| 5 | T016-T021 | 10 | gRPC, WebSocket, WSDL probes |
| 6 | T022-T025 | 6 | **SDK adapter, output routing, orchestrator** (REVISED) |
| **Total** | **25** | **43** | |

---

## Revision History

| Date | Change | Rationale |
|------|--------|-----------|
| 2026-01-28 | Batch 6 revised to use capability-sdk | Hybrid adapter approach approved by capability-lead + backend-lead. Reuses 5 SDK formatters instead of custom JSON/CSV. |

---

## Metadata

```json
{
  "agent": "capability-lead",
  "output_type": "implementation-plan",
  "timestamp": "2026-01-27T00:00:00Z",
  "revised_at": "2026-01-28T00:00:00Z",
  "feature_directory": "/Users/nathansportsman/capabilities/modules/vespasian/.capability-development",
  "skills_invoked": ["writing-plans", "adhering-to-dry", "adhering-to-yagni", "enforcing-evidence-based-analysis"],
  "library_skills_read": [
    ".claude/skill-library/development/capabilities/implementing-detection-plugins/SKILL.md",
    ".claude/skill-library/development/capabilities/implementing-go-plugin-registries/SKILL.md",
    ".claude/skill-library/development/capabilities/integrating-standalone-capabilities/SKILL.md"
  ],
  "source_files_verified": [
    "/Users/nathansportsman/capabilities/modules/nerva/pkg/plugins/types.go:345-351",
    "/Users/nathansportsman/capabilities/modules/augustus/pkg/registry/registry.go:1-150",
    "/Users/nathansportsman/capabilities/modules/capability-sdk/pkg/formatter/*"
  ],
  "sdk_integration": {
    "decision": "hybrid-adapter",
    "sdk_dependency": "github.com/praetorian-inc/capability-sdk",
    "output_formats": ["terminal", "json", "ndjson", "markdown", "sarif"],
    "analysis_file": ".capability-development/agents/capability-lead-architecture-review.md"
  },
  "status": "complete",
  "handoff": {
    "next_agent": "capability-developer",
    "context": "Execute Batch 6 with SDK integration. Create pkg/output/adapter.go and pkg/output/writer.go using capability-sdk formatters."
  }
}
```
