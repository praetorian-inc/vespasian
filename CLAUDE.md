# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Vespasian is an API discovery and specification generation tool for security assessments. It captures HTTP traffic through headless browser crawling or imports it from existing sources (Burp Suite XML, HAR, mitmproxy), classifies requests by API type (REST, GraphQL, SOAP/WSDL, gRPC), probes discovered endpoints, and generates specifications in the native format for each type: OpenAPI 3.0, GraphQL SDL, WSDL, or `.proto`. gRPC is opt-in (`--api-type grpc`) since its binary HTTP/2 framing is not auto-detected.

## Build and Test Commands

```bash
# Build
make build                    # Build binary to bin/vespasian

# Run all tests with race detection
make test                     # Equivalent to: go test -race ./...

# Run tests for a specific package
go test ./pkg/classify/...

# Run a single test
go test -run TestFunctionName ./pkg/package/...

# Lint
make lint                     # Runs golangci-lint (gocritic, misspell, revive)

# Format
make fmt                      # Runs gofmt -s -w .

# All checks (format, vet, lint, test)
make check

# Coverage
make coverage                 # Generates coverage.out and prints per-function coverage

# Dependencies
make deps                     # go mod download && go mod tidy

# Clean
make clean                    # Remove bin/, dist/, coverage.out

# Live test services
make live-test-clean          # Stop live test services (escape hatch for orphaned processes)
```

## Architecture

### Two-Stage Pipeline

Vespasian separates traffic capture from specification generation:

1. **Capture**: Crawl a target with a headless browser or import traffic from Burp/HAR/mitmproxy → produces `capture.json` (array of `ObservedRequest`)
2. **Generate**: Classify requests → probe endpoints → generate specification (OpenAPI 3.0, GraphQL SDL, WSDL, or `.proto`)

The `scan` command combines both stages. The `crawl`/`import` and `generate` commands run them independently.

### Core Flow

The CLI (`cmd/vespasian`) uses Kong for argument parsing. Each command (crawl, import, generate, scan) has a `Run()` method. The scan pipeline:

1. Crawl target URL → `[]crawl.ObservedRequest`
2. Augment requests with static HTML form analysis via `analyze.ExtractForms()` (emits synthetic `ObservedRequest` entries with `Source="static:html"` for every `<form>` in HTML response bodies) — done **before** auto-detection so form-derived REST signals feed the heuristic
3. Auto-detect API type (or use explicit `--api-type`)
4. Classify requests via `classify.RunClassifiers()` with confidence threshold
5. Deduplicate classified endpoints
6. Probe endpoints via `probe.RunStrategies()` (OPTIONS, schema, WSDL fetch, GraphQL introspection, gRPC reflection, gRPC-gateway OpenAPI)
7. Generate spec via `generate.Get(apiType).Generate()`

Note: `detectAPIType` (auto mode) runs only the REST/WSDL/GraphQL classifiers — gRPC is never auto-selected and requires explicit `--api-type grpc`. Under `--api-type grpc`, three reflection-off-capable techniques are chained in priority order: server reflection (richest — real message fields) → grpc-gateway OpenAPI scrape → gRPC-Web JS-binding recovery from the capture. The first two are `ProbeStrategy` implementations run by `RunStrategies`; the binding recovery is applied afterward (`enrichGRPCFromBindings`) because it reads JS bodies from the full capture rather than the network. Reflection results are never overwritten by the name-only techniques. All three run only inside the `scan`/`generate` pipeline — there is no standalone `probe` CLI command.

### Key Packages

- **cmd/vespasian**: CLI entry point, command definitions, signal handling, browser lifecycle management
- **internal/pipeline**: Shared crawl/classify/probe/generate orchestration consumed by both the CLI (`cmd/vespasian`) and the SDK (`pkg/sdk`). Exports `DetectAPIType`, `ClassifiersForType`, `StrategiesForType`, `ClassifyProbeGenerate`, `ResolveWSDLType`, `ProbeAndAppendWSDLRequest`, `ProbeWSDLDocument`, `IsStaticAssetURL`, `Augment`/`AnalyzeJS` (forms-then-jsstatic augmentation; `AnalyzeJS` is the JS-only stage CrawlCmd runs at crawl time), and `ResolveAndGenerate` (the bundled detect → wsdl-resolve → optional `AfterWSDL` hook → classify/probe/generate sequence; the CLI passes its JS-replay step as the `AfterWSDL` hook, the SDK passes nil). The gRPC path also chains grpc-gateway OpenAPI probing and gRPC-Web JS-binding enrichment (reflection > gateway > bindings) within the classify/probe/generate sequence.
- **pkg/crawl**: Two crawler backends — headless mode uses go-rod to drive Chrome tabs (full JS/SPA support); non-headless mode uses a stdlib net/http engine with DFS frontier, 150 rps rate limiter, and scope+SSRF redirect guard. Both produce `ObservedRequest` values. Both honor `--proxy` (http/https/socks5, validated by `ValidateProxyAddr`): the headless path routes Chrome via `--proxy-server`, the HTTP path wires `http.ProxyURL` into the transport. With `--proxy`, TLS verification stays on by default; `--proxy-insecure` disables it for http/https intercepting proxies (Burp/mitmproxy MITM) on the HTTP path only (socks5 always keeps verification, since the Go client does TLS directly to the target through the tunnel; the headless backend validates against the OS trust store, so trust the proxy CA out-of-band there). The HTTP path also skips its dial-time SSRF pin for the proxy connection (URL-level scope still applies, so private targets still need `--dangerous-allow-private`). Only crawl traffic is proxied; the probe and JS-replay stages are not proxy-aware. Also owns capture file I/O and browser manager lifecycle, and the post-crawl JS-replay step (`ReplayJSExtracted`) that rescans captured JS bundles for API paths and probes them with raw HTTP under same-origin and SSRF protections. JS-replay is driven by the `scan` pipeline only — it re-fetches bundles and probes the live target, so it requires a target URL and does not run in the offline `generate` command (which has no target URL). Offline JS analysis in `generate` is handled separately by `pkg/analyze/jsstatic` via `--analyze-js`. The extractor reconstructs paths from quoted strings, template literals, full URLs, service-prefix concatenation, and `String.prototype.concat`/`+`-string concatenation (substituting a numeric sentinel for non-literal operands so the path stays probeable and parameterizable)
- **pkg/ssrf**: Leaf package providing `ValidateURL` and `SafeDialContext` for SSRF protection (rejects private/loopback/link-local destinations and re-resolves at connect time to defeat DNS rebinding); imported by both `pkg/probe` and `pkg/crawl`
- **pkg/analyze**: Static analysis of captured HTML response bodies; extracts `<form>` endpoints and parameter names as synthetic `ObservedRequest` entries (`Source="static:html"`) to surface form-based APIs not triggered during crawl. Also hosts `ExtractGRPCWebBindings`, which runs jsluice over captured JS bodies to recover gRPC service/method/type names and streaming flags from generated gRPC-Web/Connect-ES client artifacts (names only; no message fields).
- **pkg/classify**: Request classification engine with confidence-based heuristics; classifiers for REST, GraphQL, WSDL, and gRPC; deduplication
- **pkg/probe**: Active endpoint probing strategies (OPTIONS discovery, JSON schema inference, WSDL document fetching, GraphQL introspection with 3-tier WAF bypass, gRPC server reflection, grpc-gateway OpenAPI scrape); SSRF protection with DNS rebinding mitigation (also applied to gRPC dial via a configurable `Config.Dialer`). The `GRPCGatewayProbe` fetches a bounded set of well-known swagger/OpenAPI paths over HTTP, recognizes grpc-gateway documents by their `operationId`/`tags` shape, and records the recovered service names on the endpoint's `GRPCSchema`; descriptor synthesis is deferred to `pkg/generate/grpc` (`FileDescriptorsFromServices`).
- **pkg/generate**: Spec generation interface and registry; delegates to sub-packages by API type
- **pkg/generate/rest**: OpenAPI 3.0 generation, path normalization (UUID detection, context-aware parameter naming), JSON schema inference, form-encoded and multipart request-body inference
- **pkg/generate/graphql**: GraphQL SDL generation from introspection results or traffic-based inference
- **pkg/generate/wsdl**: WSDL generation from SOAP traffic, WSDL document parsing, type inference from SOAP envelopes
- **pkg/generate/grpc**: `.proto` (proto3) generation from gRPC reflection descriptors via `jhump/protoreflect`'s `protoprint`. Reconstructs the `FileDescriptorProto` graph captured by the probe and renders deterministic source (sorted files/elements, `google/protobuf/*` well-known files omitted). Requires reflection `FileDescriptors`; traffic-only inference is not yet implemented and returns an error. `FileDescriptorsFromServices` is the name-only entry point: it synthesizes `FileDescriptorProto` wire bytes (empty message stubs, streaming flags preserved) from `[]classify.GRPCService` recovered by the reflection-off techniques (grpc-gateway OpenAPI, gRPC-Web bindings) and feeds them through the same `Generate`/`renderProto` path so all techniques emit byte-identical formatting. Synthetic filenames are namespaced (`<pkg>/synthetic.proto`) so they never collide with reflection's real descriptor filenames.
- **pkg/analyze/jsstatic**: Static analysis of captured JavaScript bundles using BishopFox/jsluice. Sits between the capture stage and classify/generate stages. Recovers API endpoints, HTTP methods, path parameters (via EXPR→{param} normalization), and request-body field names (from `fetch`/`axios` object literals). Synthesises `crawl.ObservedRequest` entries with `Source="static:js"` or `"static:js-sourcemap"` and appends them after dynamic entries so `classify.Deduplicate` keeps dynamic observations on ties. Enabled by default; opt out with `--analyze-js=false`.
- **pkg/importer**: Traffic importers for Burp Suite XML, HAR 1.2, and mitmproxy dumps (including mitmproxy's native tnetstring `.mitm` format); format registry with layered safety caps — 500 MB per file, 64 MB per tnetstring element, 1 M entries per list/dict, 500 K flows per native stream
- **pkg/mediatype**: Shared media-type canonicalization (lowercase + parameter strip). Used by classify and generate/rest where an import cycle prevents direct sharing.
- **pkg/sdk**: Implements the capability-sdk `Capability[capmodel.WebApplication]` interface, exposing the vespasian pipeline to chariot/Guard hosts. The standalone CLI does not import this package.
- **internal/grpcwire**: gRPC length-prefixed framing + protobuf wire-format parser (ParseFrame, ParseVarint, ParseTag, WalkFields). Not yet wired into the classifier, probe, or generator — it is foundation reserved for the future traffic-inference path that `pkg/generate/grpc` does not yet implement (the generator currently relies on reflection descriptors).

### Key Patterns

- **Registry pattern**: Both `pkg/importer` and `pkg/generate` use a registry map to look up implementations by name (`Get()` function)
- **Strategy pattern**: `pkg/probe` defines `ProbeStrategy` interface; each probe type (Options, Schema, WSDL, GraphQL, gRPC reflection, grpc-gateway) is a separate implementation
- **Classifier interface**: `pkg/classify` defines `APIClassifier` interface; each API type has its own classifier with heuristic rules and confidence scores

### Capture Format

The intermediate `capture.json` file is a JSON array of `crawl.ObservedRequest` structs. Each entry contains method, URL, headers, body, and response data. This format is shared between crawl output, importer output, and generator input.

The `query_params` field is `map[string][]string` (multi-value). Capture files generated by versions ≤ LAB-2110 use the older `map[string]string` shape and are NOT compatible — re-run capture against the target.

## CLI Commands

| Command   | Purpose |
|-----------|---------|
| `scan`    | Full pipeline: crawl + classify + probe + generate. Flags: `--analyze-js` (default true), `--fetch-sourcemaps` (default true), `--merge-slugs` (default false), `--slug-threshold` (default 2), `--grpc-insecure-skip-verify` (default false; opt-in TLS trust-chain skip for gRPC reflection) |
| `crawl`   | Capture traffic via headless browser → capture.json. Flags: `--analyze-js` (default true), `--fetch-sourcemaps` (default true) |
| `import`  | Convert Burp XML / HAR / mitmproxy → capture.json |
| `generate` | Produce spec from capture.json (REST→OpenAPI, GraphQL→SDL, WSDL→WSDL, gRPC→`.proto`). Flags: `--analyze-js` (default true), `--fetch-sourcemaps` (default false), `--merge-slugs` (default false), `--slug-threshold` (default 2), `--grpc-insecure-skip-verify` (default false). `grpc` must be passed explicitly; unlike the other types it is **not** fully offline — descriptors are not stored in the capture (`FileDescriptors` is `json:"-"`), so `generate grpc` re-runs the reflection probe live against the gRPC targets in the capture (needs `--probe`, on by default, and target reachability). |
| `version` | Show version information |

## Test Infrastructure

The `test/` directory contains live test targets:

- **test/rest-api/**: Go HTTP server exposing REST endpoints for end-to-end testing
- **test/soap-service/**: Go HTTP server exposing SOAP/WSDL endpoints
- **test/graphql-server/**: Node.js GraphQL server with Apollo
- **test/grpc-server/**: Go gRPC server with Server Reflection enabled (sample User/Order/Account services, including a streaming method) for reflection-probe testing

See `test/README.md` for how to run the suite, including the `TEST_HOST` override for devcontainer setups.

## Code Conventions

- Go file naming: lowercase with underscores (e.g., `rest_classifier.go`, not `restClassifier.go`)
- Test files match source files (`foo.go` → `foo_test.go`)
- Formatting enforced by `gofmt -s` (run `make fmt`)
- Linting via `golangci-lint` with gocritic, misspell, revive (run `make lint`)
- Package-level documentation lives in `doc.go` files

## Development Workflow

- After implementing a feature or fix, run `make check` to ensure all tests and the linter pass.
- After modifying a Go source file, update its package's `doc.go` if the change affects the package's public API or purpose.
- After adding or changing features, review `README.md` and `CLAUDE.md` for accuracy and update them if needed.

## CI

GitHub Actions runs on push to main and PRs:

- **ci.yml**: Build, test (`go test -race`, 80% coverage threshold), lint (golangci-lint v2), and format check. Runs on all pushes and PRs.
- **live-tests.yml**: A single **test** job runs all targets via `test/run-live-tests.sh --group offline` then `--group live`. Target groups (`OFFLINE_TARGETS` / `LIVE_TARGETS`) are defined in `test/run-live-tests.sh` — the workflow references groups, not individual targets, so adding a target means editing one array in the runner. A drift-guard step (`test/test-runner-args.sh`) fails CI if a dispatch target is not covered by `OFFLINE_TARGETS`, `LIVE_TARGETS`, or the config-only set (e.g. `grpc-server`). Uses the stable Chrome shipped with the ubuntu-24.04 runner. Runs on every PR by default; add the `skip-live-tests` label to bypass. Always runs on push to `main` and `workflow_dispatch`. The `preflight-selftest` and `test` jobs open with a `step-security/harden-runner` step in `egress-policy: audit` mode (LAB-4732 / SEC-BE-002) — defense-in-depth network monitoring that logs (does not block) outbound traffic.
