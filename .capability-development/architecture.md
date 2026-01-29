# Vespasian Architecture Design

> **Capability Lead:** capability-lead agent
> **Date:** 2026-01-27
> **Version:** 1.0

## Executive Summary

Vespasian is a comprehensive API surface enumeration tool that extends beyond traditional web crawling to discover API endpoints through multiple probe types. The architecture follows proven patterns from Nerva (plugin interface), Augustus (generic registry), and Hadrian (YAML templates).

**Key Design Decisions:**
- Standalone reimplementation (not Katana wrapper)
- Static registration via `init()` pattern
- Hybrid approach: Go plugins for complex logic, YAML templates for pattern matching
- Phase 1 MVP: Core crawling + 5 new probes (OpenAPI, GraphQL, gRPC, WebSocket, WSDL)

---

## 1. Package Structure

```
vespasian/
├── cmd/vespasian/
│   └── main.go                     # CLI entrypoint (Kong/Cobra)
│
├── pkg/
│   ├── probes/                     # Probe interfaces + base implementations
│   │   ├── probe.go                # Base Probe interface
│   │   ├── http_probe.go           # HTTPProbe interface (extends Probe)
│   │   ├── protocol_probe.go       # ProtocolProbe interface (extends Probe)
│   │   └── types.go                # ProbeResult, ProbeConfig, etc.
│   │
│   ├── registry/                   # Generic registry (ported from Augustus)
│   │   └── registry.go             # Registry[T] with sync.RWMutex
│   │
│   ├── http/                       # HTTP client with rate limiting
│   │   ├── client.go               # HTTP client wrapper
│   │   ├── ratelimit.go            # Token bucket rate limiter
│   │   └── transport.go            # Custom transport with retries
│   │
│   ├── crawler/                    # HTTP crawling engine
│   │   ├── crawler.go              # Main crawler orchestrator
│   │   ├── parser.go               # HTML/JS link extraction
│   │   └── scope.go                # URL scope enforcement
│   │
│   ├── spec/                       # API specification parsers
│   │   ├── openapi/
│   │   │   ├── parser.go           # OpenAPI 2.0/3.0/3.1 parser
│   │   │   └── probe.go            # OpenAPI probe implementation
│   │   ├── graphql/
│   │   │   ├── introspection.go    # GraphQL introspection query
│   │   │   └── probe.go            # GraphQL probe implementation
│   │   └── wsdl/
│   │       ├── parser.go           # WSDL 1.1/2.0 parser
│   │       └── probe.go            # WSDL/SOAP probe implementation
│   │
│   ├── protocols/                  # Non-HTTP protocol implementations
│   │   ├── grpc/
│   │   │   ├── reflection.go       # gRPC reflection client
│   │   │   └── probe.go            # gRPC probe implementation
│   │   └── websocket/
│   │       ├── client.go           # WebSocket client
│   │       └── probe.go            # WebSocket probe implementation
│   │
│   ├── js/                         # JavaScript parsing
│   │   ├── parser.go               # JS static analysis
│   │   └── xhr.go                  # XHR/fetch endpoint extraction
│   │
│   ├── config/                     # YAML configuration loading
│   │   ├── config.go               # Config struct and loader
│   │   └── validate.go             # Config validation
│   │
│   ├── discovery/                  # Output structures
│   │   ├── endpoint.go             # APIEndpoint definition
│   │   ├── result.go               # DiscoveryResult aggregation
│   │   └── dedupe.go               # Endpoint deduplication
│   │
│   └── output/                     # Output formatters
│       ├── json.go                 # JSON output
│       ├── csv.go                  # CSV output
│       └── nuclei.go               # Nuclei template generation
│
├── templates/                      # YAML probe templates
│   ├── patterns/                   # Detection patterns
│   │   ├── openapi.yaml            # OpenAPI detection patterns
│   │   ├── graphql.yaml            # GraphQL detection patterns
│   │   └── swagger-ui.yaml         # Swagger UI detection
│   └── wordlists/                  # Discovery wordlists
│       ├── api-paths.txt           # Common API paths
│       └── spec-locations.txt      # Common spec file locations
│
├── internal/                       # Private implementation
│   ├── queue/                      # URL queue management
│   │   └── queue.go                # Thread-safe priority queue
│   └── browser/                    # Headless browser (Phase 2)
│       └── chromedp.go             # ChromeDP integration
│
└── testdata/                       # Test fixtures
    ├── openapi/                    # OpenAPI spec samples
    ├── graphql/                    # GraphQL schema samples
    └── wsdl/                       # WSDL samples
```

---

## 2. Probe Interface Hierarchy

### 2.1 Base Probe Interface

```go
// pkg/probes/probe.go

// Probe is the base interface for all discovery probes.
// Follows Nerva pattern: Run(), Name(), Priority()
type Probe interface {
    // Run executes the probe against a target and returns discovered endpoints.
    Run(ctx context.Context, target Target, opts ProbeOptions) (*ProbeResult, error)

    // Name returns the unique probe identifier.
    Name() string

    // Category returns the probe category (http, protocol, data).
    Category() ProbeCategory

    // Priority returns execution priority (lower = higher priority).
    // Used for probe ordering within a category.
    Priority() int

    // Accepts returns true if the probe can handle the given target.
    // Enables probe filtering based on target characteristics.
    Accepts(target Target) bool
}

// ProbeCategory classifies probes for execution ordering
type ProbeCategory int

const (
    CategoryHTTP     ProbeCategory = iota // HTTP-based discovery
    CategoryProtocol                       // Non-HTTP protocols (gRPC, WebSocket)
    CategoryData                           // File-based (HAR, mobile) - P2
)
```

### 2.2 Specialized Probe Interfaces

```go
// pkg/probes/http_probe.go

// HTTPProbe extends Probe for HTTP-based discovery.
type HTTPProbe interface {
    Probe

    // RequiresAuth returns true if the probe needs authentication.
    RequiresAuth() bool

    // HTTPMethods returns HTTP methods the probe uses.
    HTTPMethods() []string
}

// CrawlerProbe is an HTTPProbe that performs link crawling.
type CrawlerProbe interface {
    HTTPProbe

    // Crawl performs recursive link extraction.
    Crawl(ctx context.Context, target Target, depth int) (*ProbeResult, error)
}

// SpecProbe is an HTTPProbe that parses API specifications.
type SpecProbe interface {
    HTTPProbe

    // ParseSpec parses a specification from raw bytes.
    ParseSpec(data []byte) ([]APIEndpoint, error)

    // DetectSpec attempts to locate specification files.
    DetectSpec(ctx context.Context, baseURL string) ([]string, error)
}
```

```go
// pkg/probes/protocol_probe.go

// ProtocolProbe extends Probe for non-HTTP protocols.
type ProtocolProbe interface {
    Probe

    // Protocol returns the protocol type (grpc, websocket, etc.)
    Protocol() string

    // DefaultPorts returns common ports for this protocol.
    DefaultPorts() []int
}
```

### 2.3 Probe Types Summary

| Interface       | Category   | Examples                        | Key Methods                |
|-----------------|------------|---------------------------------|----------------------------|
| `Probe`         | Base       | All probes                      | Run, Name, Priority        |
| `HTTPProbe`     | HTTP       | Crawler, OpenAPI, GraphQL, WSDL | RequiresAuth, HTTPMethods  |
| `CrawlerProbe`  | HTTP       | Standard crawler, JS parser     | Crawl                      |
| `SpecProbe`     | HTTP       | OpenAPI, GraphQL, WSDL          | ParseSpec, DetectSpec      |
| `ProtocolProbe` | Protocol   | gRPC, WebSocket                 | Protocol, DefaultPorts     |

---

## 3. Registry Pattern Implementation

### 3.1 Generic Registry (Ported from Augustus)

```go
// pkg/registry/registry.go

package registry

import (
    "fmt"
    "sort"
    "sync"
)

// Config holds configuration for probe instantiation.
type Config map[string]any

// Registry manages registered probes of a specific type.
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

// Register adds a factory function for the given probe name.
// Called from init() in probe implementation files.
func (r *Registry[T]) Register(name string, factory func(Config) (T, error)) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.factories[name] = factory
}

// Create instantiates a probe by name with the given config.
// Returns new instance each call (factory pattern, not singleton).
func (r *Registry[T]) Create(name string, cfg Config) (T, error) {
    r.mu.RLock()
    factory, ok := r.factories[name]
    r.mu.RUnlock()

    if !ok {
        var zero T
        return zero, fmt.Errorf("probe not found: %s", name)
    }

    return factory(cfg)
}

// List returns all registered probe names, sorted alphabetically.
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

// Has checks if a probe is registered.
func (r *Registry[T]) Has(name string) bool {
    r.mu.RLock()
    defer r.mu.RUnlock()
    _, ok := r.factories[name]
    return ok
}
```

### 3.2 Probe Registration

```go
// pkg/probes/registry.go

package probes

import "github.com/praetorian-inc/vespasian/pkg/registry"

// Global probe registry
var Registry = registry.New[Probe]("probes")

// Register adds a probe factory to the global registry.
// Called from init() in each probe implementation.
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
```

### 3.3 init() Self-Registration Pattern

```go
// pkg/spec/openapi/probe.go

package openapi

import (
    "github.com/praetorian-inc/vespasian/pkg/probes"
    "github.com/praetorian-inc/vespasian/pkg/registry"
)

func init() {
    probes.Register("openapi", func(cfg registry.Config) (probes.Probe, error) {
        return NewProbe(cfg)
    })
}

type Probe struct {
    config *Config
    client *http.Client
}

func NewProbe(cfg registry.Config) (*Probe, error) {
    // Parse config, initialize probe
    return &Probe{}, nil
}

func (p *Probe) Name() string { return "openapi" }
func (p *Probe) Category() probes.ProbeCategory { return probes.CategoryHTTP }
func (p *Probe) Priority() int { return 10 }
// ... implement remaining interface methods
```

---

## 4. Output Schema (APIEndpoint)

```go
// pkg/discovery/endpoint.go

package discovery

import (
    "encoding/json"
    "time"
)

// APIEndpoint represents a discovered API endpoint.
type APIEndpoint struct {
    // Core identification
    URL        string `json:"url"`                   // Full URL
    Path       string `json:"path"`                  // Path component only
    Method     string `json:"method"`                // HTTP method (GET, POST, etc.)

    // Discovery metadata
    Source     string `json:"source"`                // Probe that discovered this (openapi, crawler, graphql)
    SourceFile string `json:"source_file,omitempty"` // Spec file if applicable
    Confidence string `json:"confidence"`            // high, medium, low

    // Endpoint characteristics
    Protocol   string            `json:"protocol"`             // http, https, ws, wss, grpc
    Parameters []Parameter       `json:"parameters,omitempty"` // Query/path/body parameters
    Headers    map[string]string `json:"headers,omitempty"`    // Required headers

    // Authentication
    AuthRequired bool     `json:"auth_required"`           // Requires authentication
    AuthTypes    []string `json:"auth_types,omitempty"`    // bearer, basic, apikey, oauth2

    // Response metadata (if probed)
    StatusCode   int    `json:"status_code,omitempty"`   // Response status
    ContentType  string `json:"content_type,omitempty"`  // Response content type
    ResponseSize int    `json:"response_size,omitempty"` // Response body size

    // API specification metadata
    OperationID string   `json:"operation_id,omitempty"` // OpenAPI operationId
    Tags        []string `json:"tags,omitempty"`         // API tags
    Summary     string   `json:"summary,omitempty"`      // Endpoint summary
    Deprecated  bool     `json:"deprecated,omitempty"`   // Deprecated flag

    // Discovery timestamp
    DiscoveredAt time.Time `json:"discovered_at"`

    // Raw metadata for custom processing
    Raw json.RawMessage `json:"raw,omitempty"`
}

// Parameter represents an API parameter
type Parameter struct {
    Name     string `json:"name"`
    In       string `json:"in"`       // path, query, header, body
    Type     string `json:"type"`     // string, integer, boolean, array, object
    Required bool   `json:"required"`
    Example  string `json:"example,omitempty"`
}

// DiscoveryResult aggregates results from multiple probes
type DiscoveryResult struct {
    Target    string        `json:"target"`
    StartTime time.Time     `json:"start_time"`
    EndTime   time.Time     `json:"end_time"`
    Duration  time.Duration `json:"duration"`

    // Endpoints discovered
    Endpoints []APIEndpoint `json:"endpoints"`

    // Statistics
    Stats DiscoveryStats `json:"stats"`

    // Errors encountered
    Errors []ProbeError `json:"errors,omitempty"`
}

// DiscoveryStats provides discovery statistics
type DiscoveryStats struct {
    TotalEndpoints   int            `json:"total_endpoints"`
    UniqueEndpoints  int            `json:"unique_endpoints"`
    BySource         map[string]int `json:"by_source"`          // endpoints per probe
    ByMethod         map[string]int `json:"by_method"`          // endpoints per HTTP method
    ByProtocol       map[string]int `json:"by_protocol"`        // endpoints per protocol
    AuthRequired     int            `json:"auth_required"`      // requiring auth
    SpecsFound       int            `json:"specs_found"`        // OpenAPI/GraphQL specs found
}

// ProbeError records probe-specific errors
type ProbeError struct {
    Probe   string `json:"probe"`
    Message string `json:"message"`
    URL     string `json:"url,omitempty"`
}
```

---

## 5. Data Flow

```
                                    ┌─────────────────┐
                                    │   CLI/Config    │
                                    │  (Kong/Cobra)   │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │  Discovery      │
                                    │  Orchestrator   │
                                    └────────┬────────┘
                                             │
              ┌──────────────────────────────┼──────────────────────────────┐
              │                              │                              │
              ▼                              ▼                              ▼
     ┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
     │  HTTP Probes    │           │ Protocol Probes │           │   Data Probes   │
     │                 │           │                 │           │    (Phase 2)    │
     │ - Crawler       │           │ - gRPC          │           │                 │
     │ - OpenAPI       │           │ - WebSocket     │           │ - HAR Parser    │
     │ - GraphQL       │           │                 │           │ - Mobile Apps   │
     │ - WSDL          │           │                 │           │                 │
     │ - JS Parser     │           │                 │           │                 │
     └────────┬────────┘           └────────┬────────┘           └────────┬────────┘
              │                              │                              │
              └──────────────────────────────┼──────────────────────────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   Aggregator    │
                                    │  (Deduplication │
                                    │   + Merging)    │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   Output        │
                                    │  JSON/CSV/      │
                                    │  Nuclei/Stdout  │
                                    └─────────────────┘
```

### 5.1 Execution Flow

1. **CLI Parsing**: Kong/Cobra parses arguments, loads config
2. **Target Resolution**: Resolve target URL, determine scope
3. **Probe Selection**: Based on config, select active probes
4. **Concurrent Execution**:
   - HTTP probes run in parallel (controlled concurrency)
   - Protocol probes run after initial HTTP discovery
5. **Result Aggregation**:
   - Deduplicate by URL+Method
   - Merge metadata from multiple sources
6. **Output Generation**: Format results per output config

---

## 6. Execution Flow Details

### 6.1 CLI Entrypoint

```go
// cmd/vespasian/main.go

func main() {
    cli := &CLI{}
    ctx := kong.Parse(cli)

    switch ctx.Command() {
    case "scan <target>":
        runScan(cli.Scan)
    case "list-probes":
        listProbes()
    case "version":
        printVersion()
    }
}
```

### 6.2 Configuration

```yaml
# vespasian.yaml
target: "https://api.example.com"
output:
  format: json
  file: "results.json"

# Probe configuration
probes:
  enabled:
    - crawler
    - openapi
    - graphql
    - grpc
    - websocket
    - wsdl

  crawler:
    depth: 3
    concurrent: 10
    scope: "same-host"  # same-host, same-domain, custom

  openapi:
    locations:
      - "/openapi.json"
      - "/swagger.json"
      - "/api-docs"
    versions: ["2.0", "3.0", "3.1"]

  graphql:
    introspection: true
    common_paths:
      - "/graphql"
      - "/api/graphql"
      - "/query"

  grpc:
    reflection: true
    ports: [50051, 9090]

# Rate limiting
rate_limit:
  requests_per_second: 10
  burst: 20

# Authentication (optional)
auth:
  type: "bearer"
  token: "${API_TOKEN}"
```

### 6.3 Discovery Orchestrator

```go
// pkg/discovery/orchestrator.go

type Orchestrator struct {
    probes    []probes.Probe
    client    *http.Client
    rateLimit *ratelimit.Limiter
    results   chan *probes.ProbeResult
}

func (o *Orchestrator) Run(ctx context.Context, target Target) (*DiscoveryResult, error) {
    // 1. Initialize result aggregator
    agg := NewAggregator()

    // 2. Group probes by category for ordered execution
    httpProbes := filterByCategory(o.probes, probes.CategoryHTTP)
    protocolProbes := filterByCategory(o.probes, probes.CategoryProtocol)

    // 3. Execute HTTP probes (concurrent, rate-limited)
    var wg sync.WaitGroup
    sem := semaphore.NewWeighted(int64(o.config.Concurrency))

    for _, probe := range httpProbes {
        if !probe.Accepts(target) {
            continue
        }

        wg.Add(1)
        go func(p probes.Probe) {
            defer wg.Done()
            if err := sem.Acquire(ctx, 1); err != nil {
                return
            }
            defer sem.Release(1)

            result, err := p.Run(ctx, target, o.probeOpts)
            if err != nil {
                agg.AddError(p.Name(), err)
                return
            }
            agg.Add(result)
        }(probe)
    }
    wg.Wait()

    // 4. Execute protocol probes (may depend on HTTP discovery)
    for _, probe := range protocolProbes {
        result, err := probe.Run(ctx, target, o.probeOpts)
        if err != nil {
            agg.AddError(probe.Name(), err)
            continue
        }
        agg.Add(result)
    }

    // 5. Return aggregated results
    return agg.Result(), nil
}
```

---

## 7. YAML Template Pattern (Detection Patterns)

Following Hadrian's template pattern for extensible detection:

```yaml
# templates/patterns/openapi.yaml
id: openapi-detection
info:
  name: "OpenAPI Specification Detection"
  category: "api-spec"

detection:
  paths:
    - "/openapi.json"
    - "/openapi.yaml"
    - "/swagger.json"
    - "/swagger.yaml"
    - "/api-docs"
    - "/v1/api-docs"
    - "/v2/api-docs"
    - "/v3/api-docs"
    - "/docs/api"
    - "/.well-known/openapi.json"

  matchers:
    - type: content-type
      values:
        - "application/json"
        - "application/yaml"
        - "text/yaml"

    - type: body-contains
      values:
        - '"openapi":'
        - '"swagger":'
        - 'openapi:'
        - 'swagger:'

  validation:
    - type: json-schema
      field: "openapi"
      pattern: "^[23]\\.\\d+\\.\\d+$"
    - type: json-schema
      field: "info.title"
      required: true
```

---

## 8. Key Design Decisions

### 8.1 Why Standalone (Not Katana Wrapper)

| Factor | Katana Wrapper | Standalone | Decision |
|--------|---------------|------------|----------|
| Dependency | Tight coupling | Independent | **Standalone** |
| API Surface | Limited by Katana | Full control | **Standalone** |
| Protocol Support | HTTP only | HTTP + gRPC + WS | **Standalone** |
| Maintenance | External dependency | Internal control | **Standalone** |

### 8.2 Why Generic Registry (Augustus Pattern)

- Type-safe with Go generics
- Thread-safe (sync.RWMutex)
- Factory pattern (new instance per call)
- Proven in production (Augustus)

### 8.3 Why Hybrid Templates + Plugins

| Approach | Use Case | Rationale |
|----------|----------|-----------|
| Go Plugin | Complex protocols (gRPC, WebSocket) | Requires compiled code for protocol handling |
| Go Plugin | Stateful crawling | Manages URL queue, visited set |
| YAML Template | Detection patterns | Easy to add new patterns without recompile |
| YAML Template | Common path lists | Extensible by users |

---

## 9. Performance Considerations

### 9.1 Rate Limiting

```go
// Token bucket rate limiter
type RateLimiter struct {
    limiter *rate.Limiter
    burst   int
}

func (r *RateLimiter) Wait(ctx context.Context) error {
    return r.limiter.Wait(ctx)
}
```

### 9.2 Concurrency Control

- Bounded worker pool (semaphore pattern)
- Per-host rate limiting
- Connection pooling via http.Transport

### 9.3 Memory Efficiency

- Streaming JSON output for large result sets
- URL deduplication during crawling
- Response body size limits

---

## 10. Testing Strategy

### 10.1 Unit Tests

- Each probe: mock HTTP server, test parsing logic
- Registry: registration, creation, listing
- Output formatters: JSON/CSV generation

### 10.2 Integration Tests

- Real spec files in testdata/
- Probe + orchestrator integration
- End-to-end discovery flow

### 10.3 Live Validation (Shodan)

- Validate against real-world targets (per validating-live-with-shodan skill)
- Measure false positive/negative rates

---

## 11. Constraints Summary

| Constraint | Requirement | How Addressed |
|------------|-------------|---------------|
| No Katana duplication | Standalone implementation | Own crawler, own queue management |
| Augustus Registry pattern | Type-safe, thread-safe | Generic Registry[T] with sync.RWMutex |
| YAML templates (Hadrian) | Pattern matching | templates/ directory with YAML detection patterns |
| P0 quality | Compilation, interface contract, error handling | Strict interfaces, comprehensive error wrapping |
| Performance | Comparable to Katana | Rate limiting, semaphore pools, connection reuse |
| Extensibility | Easy probe addition | init() self-registration pattern |

---

## Metadata

```json
{
  "agent": "capability-lead",
  "output_type": "architecture-plan",
  "timestamp": "2026-01-27T00:00:00Z",
  "feature_directory": "/Users/nathansportsman/capabilities/modules/vespasian/.capability-development",
  "skills_invoked": [
    "using-skills",
    "using-todowrite",
    "persisting-agent-outputs",
    "adhering-to-dry",
    "adhering-to-yagni",
    "brainstorming",
    "calibrating-time-estimates",
    "debugging-systematically",
    "discovering-reusable-code",
    "enforcing-evidence-based-analysis",
    "gateway-backend",
    "gateway-capabilities",
    "gateway-integrations",
    "writing-plans",
    "verifying-before-completion"
  ],
  "library_skills_read": [
    ".claude/skill-library/development/capabilities/implementing-detection-plugins/SKILL.md",
    ".claude/skill-library/development/capabilities/implementing-go-plugin-registries/SKILL.md"
  ],
  "source_files_verified": [
    "/Users/nathansportsman/capabilities/modules/nerva/pkg/plugins/types.go:345-351",
    "/Users/nathansportsman/capabilities/modules/nerva/pkg/plugins/plugins.go:24-40",
    "/Users/nathansportsman/capabilities/modules/augustus/pkg/registry/registry.go:1-150",
    "/Users/nathansportsman/capabilities/modules/hadrian/hadrian-api-tester/pkg/templates/template.go:1-129",
    "/Users/nathansportsman/capabilities/modules/hadrian/hadrian-api-tester/pkg/templates/parse.go:1-101"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "capability-developer",
    "context": "Implement according to architecture.md and plan.md"
  }
}
```
