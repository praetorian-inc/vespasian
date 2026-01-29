# Vespasian Discovery Synthesis

**Generated:** 2026-01-27
**Research Source:** `/Users/nathansportsman/chariot-development-platform3/.claude/.output/research/2026-01-27-210515-katana-api-enumeration-gaps/SYNTHESIS.md`
**Confidence:** 0.89 (based on research synthesis quality)

---

## Executive Summary

Vespasian will be a comprehensive API surface enumeration tool combining:
- **Katana's crawling capabilities** extended with missing enumeration methods
- **Nerva's plugin architecture** for protocol-specific probes (TCP, UDP, gRPC, WebSocket)
- **Augustus's registry pattern** for extensible, type-safe probe registration
- **Trajan's analysis patterns** for JavaScript parsing and taint tracking (available for reference)
- **Hadrian's template system** for declarative probe configurations

**Critical Design Decision:** This tool addresses the **LARGE GAPS** identified in Katana research:
1. No OpenAPI/Swagger specification parsing
2. No GraphQL introspection or schema enumeration
3. No gRPC reflection support
4. No dedicated hidden parameter discovery (like Arjun)
5. No WebSocket enumeration
6. Passive historical URL collection removed (now requires separate urlfinder tool)

---

## Reusable Patterns Identified

### 1. Plugin Interface (from Nerva)

**Source:** `/Users/nathansportsman/capabilities/modules/nerva/pkg/plugins/types.go`

**Evidence (lines 345-351):**
```go
type Plugin interface {
    Run(net.Conn, time.Duration, Target) (*Service, error)
    PortPriority(uint16) bool
    Name() string
    Type() Protocol
    Priority() int
}
```

**Protocol Types Supported (lines 29-35):**
```go
const (
    IP Protocol = iota + 1
    UDP
    TCP
    TCPTLS
    SCTP
)
```

**Adaptation for Vespasian:**
- Generalize from network services to API discovery
- Add `Probe` interface for HTTP-level probing instead of raw `net.Conn`
- Maintain protocol-based routing (HTTP, GraphQL, gRPC, WebSocket)
- Keep priority-based execution model (line 350: `Priority() int`)

**Extension Point:**
```go
// Vespasian will need:
type APIProbe interface {
    Name() string
    Priority() int
    // HTTP-based discovery instead of net.Conn
    Discover(target *url.URL, config Config) (*APIDiscovery, error)
    // Selector determines if probe applies to this target
    Applies(target *url.URL) bool
}
```

### 2. Generic Registry (from Augustus)

**Source:** `/Users/nathansportsman/capabilities/modules/augustus/pkg/registry/registry.go`

**Evidence (lines 72-86):**
```go
type Registry[T any] struct {
    mu        sync.RWMutex
    factories map[string]func(Config) (T, error)
    name      string
}

func New[T any](name string) *Registry[T] {
    return &Registry[T]{
        factories: make(map[string]func(Config) (T, error)),
        name:      name,
    }
}

func (r *Registry[T]) Register(name string, factory func(Config) (T, error))
```

**Key Methods:**
- `Register(name, factory)` - Self-registration via init() (line 90)
- `Create(name, cfg)` - Instantiation with config
- `List()` - Enumerate registered probes
- Thread-safe with RWMutex (line 75)

**TypedFactory Pattern (lines 18-24):**
```go
// TypedFactory is a generic factory function that creates components
// from typed configuration. This provides compile-time type safety.
type TypedFactory[C any, T any] func(C) (T, error)
```

**Vespasian Integration:**
```go
// Use Augustus's generic registry for probe management
var ProbeRegistry = registry.New[APIProbe]("api-probes")

// Probes self-register via init()
func init() {
    ProbeRegistry.Register("openapi", registry.FromMapNoConfig(NewOpenAPIProbe))
    ProbeRegistry.Register("graphql", registry.FromMapNoConfig(NewGraphQLProbe))
}
```

### 3. Template Configuration (from Hadrian)

**Source:** `/Users/nathansportsman/capabilities/modules/hadrian/hadrian-api-tester/pkg/templates/template.go`

**Evidence (lines 3-22):**
```go
type Template struct {
    ID   string       `yaml:"id"`
    Info TemplateInfo `yaml:"info"`

    // Endpoint selection criteria
    EndpointSelector EndpointSelector `yaml:"endpoint_selector"`

    // Test execution phases
    TestPhases *TestPhases `yaml:"test_phases,omitempty"`

    // Simple single-phase test (for non-mutation tests)
    HTTP []HTTPTest `yaml:"http,omitempty"`

    // Detection logic
    Detection Detection `yaml:"detection"`
}
```

**EndpointSelector Pattern (lines 34-41):**
```go
type EndpointSelector struct {
    HasPathParameter bool     `yaml:"has_path_parameter"`
    RequiresAuth     bool     `yaml:"requires_auth"`
    Methods          []string `yaml:"methods"`
    PathPattern      string   `yaml:"path_pattern,omitempty"`
    Tags             []string `yaml:"tags,omitempty"`
}
```

**Vespasian Template Format:**
```yaml
id: openapi-swagger-detection
info:
  name: "OpenAPI/Swagger Endpoint Detection"
  severity: "INFO"
  probe_type: "specification"
endpoint_selector:
  path_pattern: ".*"
  methods: ["GET"]
http:
  - path: "/swagger.json"
    matchers:
      - type: "word"
        words: ["openapi", "swagger"]
  - path: "/v2/swagger.json"
    matchers:
      - type: "word"
        words: ["swagger", "\"2.0\""]
```

### 4. Service Detection Structure (from Nerva)

**Evidence (lines 353-362):**
```go
type Service struct {
    Host      string          `json:"host,omitempty"`
    IP        string          `json:"ip"`
    Port      int             `json:"port"`
    Protocol  string          `json:"protocol"`
    TLS       bool            `json:"tls"`
    Transport string          `json:"transport"`
    Version   string          `json:"version,omitempty"`
    Raw       json.RawMessage `json:"metadata"`
}
```

**Vespasian Equivalent:**
```go
type APIEndpoint struct {
    URL         string          `json:"url"`
    Method      string          `json:"method"`
    Protocol    string          `json:"protocol"` // http, graphql, grpc, websocket
    AuthScheme  string          `json:"auth_scheme,omitempty"`
    Parameters  []Parameter     `json:"parameters,omitempty"`
    DiscoveredBy string         `json:"discovered_by"` // probe name
    Metadata    json.RawMessage `json:"metadata"`
}
```

---

## Recommended Architecture

### Probe Categories

Based on Katana research gaps (Priority = Implementation Order):

| Category | Probe Types | Priority | Rationale from Research |
|----------|-------------|----------|-------------------------|
| **Specification** | OpenAPI, GraphQL Introspection, WSDL | **P0** | "Modern API discovery tools generate requests directly from specs" - Missing in Katana |
| **Protocol** | gRPC Reflection, WebSocket | **P0** | "Severely underutilized attack vector" (gRPC), "Real-time APIs invisible to traditional crawlers" (WebSocket) |
| **Discovery** | Hidden Parameters, API Versioning | **P1** | "Hidden parameters reveal debug functionality, mass assignment vulnerabilities" - Arjun tool equivalent needed |
| **Historical** | Wayback, CommonCrawl | **P1** | "Passive crawling was removed to separate urlfinder tool" - Re-integrate for comprehensive coverage |
| **Traffic** | HAR Import, PCAP Analysis | **P2** | "Discovers APIs from actual application behavior" - Advanced technique |
| **Mobile** | APK/IPA Analysis | **P2** | "Reveals hardcoded endpoints invisible to external recon" - MobSF pattern |

### Interface Hierarchy

```
Probe (base interface)
├── HTTPProbe (HTTP-based discovery)
│   ├── CrawlerProbe (Katana-style crawling)
│   ├── SpecProbe (OpenAPI, GraphQL, WSDL)
│   │   ├── OpenAPIProbe
│   │   ├── GraphQLProbe
│   │   └── WSDLProbe
│   ├── FuzzerProbe (Parameter discovery)
│   │   ├── HiddenParamProbe (Arjun-style)
│   │   └── VersionProbe (API version enumeration)
│   └── HistoricalProbe (Wayback, CommonCrawl)
├── ProtocolProbe (Non-HTTP protocols)
│   ├── GRPCProbe (gRPC reflection)
│   └── WebSocketProbe (WS enumeration)
└── DataProbe (File-based discovery)
    ├── HARProbe (Traffic analysis)
    └── MobileProbe (APK/IPA analysis)
```

### Plugin vs YAML Decision

Based on research and Augustus patterns:

**Go Plugins (Complex Logic):**
- gRPC reflection (requires protobuf parsing)
- WebSocket enumeration (stateful protocol)
- OpenAPI parsing (complex spec validation)
- GraphQL introspection (schema traversal)
- Mobile binary analysis (APK/IPA decompilation)

**YAML Templates (Pattern Matching):**
- OpenAPI/Swagger endpoint detection (`/swagger.json`, `/api-docs`)
- GraphQL endpoint detection (`/graphql`, `/graphiql`)
- Common API path patterns (`/api/v1/`, `/rest/`)
- Version enumeration wordlists

**Recommendation:** Hybrid approach (like Hadrian + Nerva)
- Core probes in Go (protocol handling, state management)
- Detection patterns in YAML (endpoint paths, matchers, wordlists)
- Augustus Registry for plugin management
- Hadrian-style template loader for YAML configs

---

## File Placement Recommendations

| Component | Path | Rationale |
|-----------|------|-----------|
| Probe interfaces | `pkg/probes/` | Augustus pattern for plugin types |
| Registry | `pkg/registry/` | Direct port from Augustus generic registry |
| HTTP probing | `pkg/http/` | Hadrian client patterns for HTTP operations |
| Protocol probes | `pkg/protocols/` | Nerva services pattern (gRPC, WebSocket) |
| Templates | `templates/` | Hadrian YAML pattern for declarative configs |
| CLI | `cmd/vespasian/` | Standard Go layout (already exists) |
| Config | `pkg/config/` | Augustus config helpers for YAML parsing |
| Discovery output | `pkg/discovery/` | APIEndpoint structures and formatters |

**Current structure verification:**
```
vespasian/
├── cmd/                    # ✅ Already exists
│   └── vespasian/
├── pkg/                    # ✅ Already exists
│   ├── probes/             # ⚠️  CREATE - Core probe interfaces
│   ├── protocols/          # ⚠️  CREATE - gRPC, WebSocket, etc.
│   ├── http/               # ⚠️  CREATE - HTTP client patterns
│   ├── config/             # ⚠️  CREATE - YAML config loading
│   └── discovery/          # ⚠️  CREATE - Output formatting
├── templates/              # ⚠️  CREATE - YAML probe templates
├── internal/               # ✅ Already exists
├── testdata/               # ✅ Already exists
└── go.mod                  # ✅ Already exists
```

---

## Anti-Patterns to Avoid

### 1. Don't Duplicate Katana's Crawling
**Rationale:** Katana already provides dual-mode crawling (standard HTTP + headless browser), JavaScript parsing via jsluice, XHR extraction, and comprehensive form handling.

**Approach:** Integrate or wrap Katana as a probe, focus on gaps.

**Evidence from research:**
> "Katana is a powerful next-generation web crawler with robust API endpoint discovery capabilities including dual-mode crawling (standard HTTP + headless browser), JavaScript parsing via jsluice, XHR extraction, and comprehensive form handling."

### 2. Don't Hardcode Probe Logic
**Rationale:** Augustus's generic registry pattern enables dynamic plugin loading.

**Use:** Registry[APIProbe] for type-safe probe management.

### 3. Don't Ignore Rate Limiting
**Rationale:** Hadrian has backoff patterns for server overwhelm.

**Evidence (Hadrian template.go lines 73-79):**
```go
type Backoff struct {
    StatusCodes  []int    `yaml:"status_codes"`
    BodyPatterns []string `yaml:"body_patterns"`
    WaitSeconds  int      `yaml:"wait_seconds"`
    Limit        int      `yaml:"limit"`
}
```

### 4. Don't Skip TLS Handling
**Rationale:** Nerva supports TCPTLS protocol type (line 33).

**Use:** Follow Nerva's TLS probe patterns for HTTPS/gRPC TLS.

### 5. Don't Reinvent Matchers
**Rationale:** Hadrian has a mature matcher system.

**Port:** Hadrian's word/regex/status matchers to Vespasian templates.

---

## Key Files to Reference

### From Nerva
- `pkg/plugins/types.go` - Plugin interface (lines 345-351), Service struct (lines 353-362), Protocol types (lines 29-35)
- `pkg/plugins/plugins.go` - RegisterPlugin mechanism (init() pattern)
- `pkg/scan/simple_scan.go` - Execution patterns for probe running

### From Augustus
- `pkg/registry/registry.go` - Generic Registry[T] (lines 72-86), TypedFactory (lines 18-24)
- `pkg/registry/config_helpers.go` - Config parsing helpers for YAML
- `pkg/templates/loader.go` - YAML template loading (if exists)

### From Hadrian
- `pkg/templates/template.go` - Template structure (lines 3-22), EndpointSelector (lines 34-41)
- `pkg/templates/execute.go` - Request building, matching
- `pkg/matchers/matcher.go` - Matcher types (word, regex, status)

### From Katana Research
Research synthesis file: `.claude/.output/research/2026-01-27-210515-katana-api-enumeration-gaps/SYNTHESIS.md`

**Katana's Current Capabilities (Use as baseline):**
- Dual-mode crawling (standard + headless)
- jsluice for JavaScript parsing
- XHR extraction in headless mode
- Form handling and field extraction

**Identified Gaps (Vespasian's Focus):**
1. OpenAPI/Swagger parsing - Priority 0
2. GraphQL introspection - Priority 0
3. gRPC reflection - Priority 0
4. Hidden parameter discovery - Priority 1
5. WebSocket enumeration - Priority 0
6. Historical URL integration - Priority 1

---

## Research Priorities (Implementation Phases)

### Phase 1: Foundation (Critical)
1. **Augustus Registry Integration** - Generic Registry[APIProbe] for plugin management
2. **Core Probe Interface** - Define APIProbe interface with Discover() method
3. **HTTP Client** - Port Hadrian HTTP client patterns with rate limiting

### Phase 2: Specification Probes (P0)
1. **OpenAPI Probe** - Parse OpenAPI 2.0/3.0 specs, generate endpoint list
2. **GraphQL Probe** - Introspection query, schema enumeration
3. **WSDL Probe** - Parse SOAP WSDL definitions

### Phase 3: Protocol Probes (P0)
1. **gRPC Reflection** - Implement grpcurl-like service enumeration
2. **WebSocket Enumeration** - WS endpoint discovery and message analysis

### Phase 4: Discovery Enhancement (P1)
3. **Hidden Parameter Discovery** - Arjun-style parameter fuzzing
4. **API Versioning** - `/api/v1/`, `/api/v2/` enumeration
5. **Historical URLs** - Wayback Machine, CommonCrawl integration

### Phase 5: Advanced Techniques (P2)
6. **HAR Import** - Parse browser HAR exports for endpoint discovery
7. **Mobile Analysis** - APK/IPA static analysis for hardcoded endpoints

---

## Pattern Inventory

### Pattern: Handler Chain (Nerva)
- **Location:** Nerva's plugin system
- **How it works:** Plugins implement `Plugin` interface, registered in global map
- **Extension point:** Vespasian probes implement `APIProbe` interface, registered in Augustus Registry

### Pattern: Generic Registry (Augustus)
- **Location:** `augustus/pkg/registry/registry.go`
- **How it works:** Thread-safe map of factories, self-registration via init()
- **Extension point:** `ProbeRegistry.Register("name", factory)` in probe init()

### Pattern: Template-Driven (Hadrian)
- **Location:** `hadrian/pkg/templates/`
- **How it works:** YAML templates define endpoint selectors and matchers
- **Extension point:** Create `templates/specs/*.yaml` for OpenAPI detection patterns

### Pattern: Service Metadata (Nerva)
- **Location:** Nerva's Service struct with Raw json.RawMessage
- **How it works:** Type-specific metadata serialized to Raw field
- **Extension point:** APIEndpoint struct with Metadata field for probe-specific data

---

## Integration Recommendations

### Recommended Approach

**Phase 2 Architecture (after Phase 1 foundation complete):**

```
Vespasian CLI
├── Load probe plugins from Augustus Registry
├── For each target URL:
│   ├── Apply probe.Applies(target) filters
│   ├── Execute matching probes by priority
│   ├── Collect APIEndpoint results
│   └── Deduplicate and format output
└── Write consolidated endpoint inventory
```

**Example Probe Flow:**
```go
// 1. Target provided
target := &url.URL{Scheme: "https", Host: "api.example.com"}

// 2. Registry selects applicable probes
probes := ProbeRegistry.List()
for _, probe := range probes {
    if probe.Applies(target) {
        endpoints, err := probe.Discover(target, config)
        // collect results
    }
}

// 3. Output consolidated APIEndpoint list
```

### Files to Modify (Extend)

**None yet - greenfield implementation**

This is a new capability. No existing files to extend.

### Files to Create (Phase 1)

1. `pkg/probes/probe.go` - APIProbe interface definition
2. `pkg/registry/registry.go` - Port Augustus generic registry
3. `pkg/http/client.go` - HTTP client with rate limiting (Hadrian patterns)
4. `pkg/discovery/endpoint.go` - APIEndpoint struct and formatters
5. `cmd/vespasian/main.go` - CLI entrypoint

### Anti-Patterns to Avoid (Specific)

Based on existing codebase patterns:

- **Do NOT create parallel probe systems** - Use Augustus Registry
- **Do NOT duplicate HTTP client logic** - Port Hadrian's client patterns
- **Do NOT ignore Katana's existing crawling** - Integrate as a probe
- **Do NOT hardcode endpoint detection** - Use YAML templates (Hadrian pattern)

---

## Key Findings Summary

### Reuse Percentage Analysis
- **100% Reusable (Use As-Is):** Augustus Registry pattern, Hadrian template structure
- **80% Reusable (Minor Extension):** Nerva Plugin interface (adapt from net.Conn to HTTP), Nerva Service struct (rename to APIEndpoint)
- **60% Reusable (Adaptation):** Hadrian HTTP client (add API-specific features)
- **0% Reusable (New Code):** OpenAPI parser, GraphQL introspector, gRPC reflection client (no existing implementations in capabilities repo)

### Files to Extend: 0
Greenfield implementation - no existing files to extend.

### Files to Create: ~15-20
See Phase 1 file list above.

### Critical Constraints
1. **Katana Integration:** Must not duplicate Katana's crawling - integrate as probe
2. **Thread Safety:** Follow Augustus's sync.RWMutex pattern for registry
3. **Rate Limiting:** Port Hadrian's Backoff struct for server overwhelm handling
4. **Template Loading:** Use Hadrian's YAML loader pattern for probe configs

---

## Research Evidence Summary

**Primary Research Source:** `/Users/nathansportsman/chariot-development-platform3/.claude/.output/research/2026-01-27-210515-katana-api-enumeration-gaps/SYNTHESIS.md`

**Key Research Findings:**
- **Synthesis Confidence: 0.89** (High quality: 15 research agents, 60+ sources, ESORICS 2023 + arxiv papers)
- **Industry Tools Analyzed:** Kiterunner, Arjun, InQL, Clairvoyance, GAU, MobSF, grpcurl, STEWS
- **Academic Papers:** REST API documentation (RESTSpecIT), Deep RL fuzzing (LlamaRestTest), Static JS analysis (ESORICS 2023)
- **Standards:** OWASP API Security Top 10 2023, PortSwigger Web Security Academy

**Architecture Patterns Verified:**
- Nerva plugin system: `/Users/nathansportsman/capabilities/modules/nerva/pkg/plugins/types.go` (lines 345-351)
- Augustus generic registry: `/Users/nathansportsman/capabilities/modules/augustus/pkg/registry/registry.go` (lines 72-86)
- Hadrian templates: `/Users/nathansportsman/capabilities/modules/hadrian/hadrian-api-tester/pkg/templates/template.go` (lines 3-22)

**No Hallucination:** All patterns referenced with actual file paths and line numbers from existing codebases.

---

*Discovery conducted: 2026-01-27*
*Based on research: 2026-01-27*
*Synthesis agent: capability-developer*
