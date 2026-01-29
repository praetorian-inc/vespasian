# Vespasian Design - Brainstorming Output

## Design Session Summary

**Date**: 2026-01-28
**Participants**: User, Claude (Orchestrator)
**Work Type**: LARGE

## Key Design Decisions

### 1. Architecture Approach

**Decision**: Standalone Reimplementation

**Rationale**:
- User wants Vespasian to be a complete replacement for Katana
- Not a wrapper or fork - full control over implementation
- Enables clean architecture optimized for extensibility

**Complexity Acknowledged**:
- Katana has 5+ years of development maturity
- We accept the upfront cost for long-term architectural control
- Crawling parity is MVP requirement, not optional
- This enables tight integration of new probes without subprocess overhead

**Phased Approach**:
- Phase 1 (MVP): Core crawling + 5 new probes (OpenAPI, GraphQL, gRPC, WebSocket, WSDL)
- Phase 2: Advanced JS parsing, performance optimization
- Phase 3: Feature parity with Katana's edge cases

**Implications**:
- Must implement core crawling from scratch
- Significant initial effort
- Maximum flexibility for future enhancements

### 2. Plugin System

**Decision**: Static Registration (init() pattern)

**Rationale**:
- Proven pattern in nerva (60+ plugins), augustus (probes/generators/detectors)
- Compile-time type safety
- Simpler deployment (single binary)
- No runtime plugin loading errors

**Implementation**:
```go
// Each probe registers itself
func init() {
    probes.Register("openapi.SwaggerDetector", NewSwaggerDetector)
}
```

### 3. MVP Feature Scope

**Crawling Parity with Katana**:
- [ ] Standard HTTP crawling (link extraction, form handling)
- [ ] Headless browser (Chrome/Playwright for JS rendering)
- [ ] JavaScript file parsing (jsluice-style endpoint extraction)
- [ ] XHR/Fetch extraction (capture async API calls)

**New Probes (P1 - MVP)**:
- [ ] OpenAPI/Swagger detection and parsing
- [ ] GraphQL introspection and schema enumeration
- [ ] gRPC reflection and service discovery
- [ ] WebSocket endpoint enumeration
- [ ] WSDL/SOAP enumeration (legacy API support)

**Deferred to P2 (Post-MVP)**:
- Hidden parameter discovery
- API version enumeration
- Historical URL aggregation (Wayback, CommonCrawl)
- HAR/PCAP import
- Mobile binary analysis (APK/IPA)

## Architecture Overview

### Probe Interface Hierarchy

```
Probe (base interface)
├── HTTPProbe (HTTP-based discovery)
│   ├── CrawlerProbe (crawling engine)
│   │   ├── StandardCrawler (net/http based)
│   │   ├── HeadlessCrawler (chromedp)
│   │   └── JSParser (endpoint extraction)
│   ├── SpecProbe (API specifications)
│   │   ├── OpenAPIProbe
│   │   ├── GraphQLProbe
│   │   └── WSDLProbe
│   └── FuzzerProbe (discovery fuzzing)
│       └── ParameterFuzzer
├── ProtocolProbe (Non-HTTP protocols)
│   ├── GRPCProbe (reflection-based)
│   └── WebSocketProbe (RFC 6455)
└── DataProbe (File-based discovery)
    ├── HARProbe (traffic analysis)
    └── MobileProbe (APK/IPA - P2)
```

### Registry Pattern

```go
// Generic registry from Augustus
type Registry[T any] struct {
    mu        sync.RWMutex
    factories map[string]func(Config) (T, error)
}

// Global registries
var ProbeRegistry = registry.New[Probe]("probes")
var MatcherRegistry = registry.New[Matcher]("matchers")
```

### Execution Flow

```
1. Parse CLI arguments
2. Load configuration
3. Initialize enabled probes
4. For each target:
   a. Run CrawlerProbes (discover endpoints)
   b. Run SpecProbes (parse discovered specs)
   c. Run ProtocolProbes (enumerate services)
   d. Run ExtractorProbes (deep analysis)
5. Aggregate results
6. Output (JSON/JSONL/stdout)
```

## Technical Considerations

### Headless Browser Strategy

**Options Evaluated**:
1. **chromedp** (Go native CDP) - Direct Chrome control
2. **rod** (Go, simpler API) - Higher-level abstraction
3. **playwright-go** - Cross-browser, feature-rich

**Recommendation**: Start with **chromedp** for:
- No external dependencies beyond Chrome
- Direct CDP access for XHR interception
- Proven in production (used by many Go tools)

### JavaScript Parsing

**Approach**: Port jsluice patterns to Go
- AST-based parsing for complex cases
- Regex patterns for simple endpoint extraction
- Handle string concatenation and template literals

### gRPC Integration

**Library**: Use grpcurl's core library
- `github.com/fullstorydev/grpcurl` provides reflection client
- Extract service discovery without external binary

### GraphQL Introspection

**Implementation**: Custom introspection query handler
- Standard introspection query
- Schema parsing into internal representation
- Query/mutation enumeration

### WebSocket Discovery

**Approach**: Based on STEWS patterns
- Detect WebSocket upgrade responses
- Enumerate common WS paths
- Message structure analysis

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Scope creep | High | High | Strict MVP definition, phase gates |
| Headless complexity | Medium | High | Start with chromedp, fallback to simpler approaches |
| Performance issues | Medium | Medium | Benchmark early, optimize hot paths |
| gRPC reflection edge cases | Low | Medium | Comprehensive test suite |

## Out of Scope for MVP

- Mobile binary analysis (APK/IPA)
- HAR/PCAP import
- Historical URL aggregation (Wayback, CommonCrawl)
- Hidden parameter discovery (P2 feature)
- API version enumeration (P2 feature)
- LLM-assisted discovery (future phase)

## Success Criteria

1. **Crawling Parity**: Match Katana's core crawling capabilities
2. **New Probes**: All 5 P1 probes functional (OpenAPI, GraphQL, gRPC, WebSocket, WSDL)
3. **Performance**: Comparable to Katana on standard targets
4. **Extensibility**: Easy to add new probes via init() pattern
5. **Testing**: ≥80% coverage on core packages

## Next Steps

1. **Phase 7**: Create detailed architecture plan with file structure
2. **Phase 8**: Implement in batches:
   - Batch 1: Core registry, CLI, configuration
   - Batch 2: Standard HTTP crawler
   - Batch 3: Headless browser, JS parsing
   - Batch 4: OpenAPI/GraphQL probes
   - Batch 5: gRPC/WebSocket/WSDL probes
3. **Phase 13**: Test each batch before proceeding
