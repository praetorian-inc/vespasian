# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Vespasian is an API discovery and specification generation tool for security assessments. It captures HTTP traffic through headless browser crawling or imports it from existing sources (Burp Suite XML, HAR, mitmproxy), classifies requests by API type (REST, GraphQL, SOAP/WSDL), probes discovered endpoints, and generates specifications in the native format for each type: OpenAPI 3.0, GraphQL SDL, or WSDL.

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
```

## Architecture

### Two-Stage Pipeline

Vespasian separates traffic capture from specification generation:

1. **Capture**: Crawl a target with a headless browser or import traffic from Burp/HAR/mitmproxy → produces `capture.json` (array of `ObservedRequest`)
2. **Generate**: Classify requests → probe endpoints → generate specification (OpenAPI 3.0, GraphQL SDL, or WSDL)

The `scan` command combines both stages. The `crawl`/`import` and `generate` commands run them independently.

### Core Flow

The CLI (`cmd/vespasian`) uses Kong for argument parsing. Each command (crawl, import, generate, scan) has a `Run()` method. The scan pipeline:

1. Crawl target URL → `[]crawl.ObservedRequest`
2. Auto-detect API type (or use explicit `--api-type`)
3. Augment requests with static HTML form analysis via `analyze.ExtractForms()` (emits synthetic `ObservedRequest` entries with `Source="static:html"` for every `<form>` in HTML response bodies)
4. Classify requests via `classify.RunClassifiers()` with confidence threshold
5. Deduplicate classified endpoints
6. Probe endpoints via `probe.RunStrategies()` (OPTIONS, schema, WSDL fetch, GraphQL introspection)
7. Generate spec via `generate.Get(apiType).Generate()`

### Key Packages

- **cmd/vespasian**: CLI entry point, command definitions, signal handling, browser lifecycle management
- **pkg/crawl**: Headless browser crawling via Katana, capture file I/O (`ObservedRequest` JSON format), browser manager with Chrome lifecycle
- **pkg/analyze**: Static analysis of captured HTML response bodies; extracts `<form>` endpoints and parameter names as synthetic `ObservedRequest` entries (`Source="static:html"`) to surface form-based APIs not triggered during crawl
- **pkg/classify**: Request classification engine with confidence-based heuristics; classifiers for REST, GraphQL, and WSDL; deduplication
- **pkg/probe**: Active endpoint probing strategies (OPTIONS discovery, JSON schema inference, WSDL document fetching, GraphQL introspection with 3-tier WAF bypass); SSRF protection with DNS rebinding mitigation
- **pkg/generate**: Spec generation interface and registry; delegates to sub-packages by API type
- **pkg/generate/rest**: OpenAPI 3.0 generation, path normalization (UUID detection, context-aware parameter naming), JSON schema inference
- **pkg/generate/graphql**: GraphQL SDL generation from introspection results or traffic-based inference
- **pkg/generate/wsdl**: WSDL generation from SOAP traffic, WSDL document parsing, type inference from SOAP envelopes
- **pkg/importer**: Traffic importers for Burp Suite XML, HAR 1.2, and mitmproxy dumps; format registry with size limits (500MB)

### Key Patterns

- **Registry pattern**: Both `pkg/importer` and `pkg/generate` use a registry map to look up implementations by name (`Get()` function)
- **Strategy pattern**: `pkg/probe` defines `ProbeStrategy` interface; each probe type (Options, Schema, WSDL, GraphQL) is a separate implementation
- **Classifier interface**: `pkg/classify` defines `APIClassifier` interface; each API type has its own classifier with heuristic rules and confidence scores

### Capture Format

The intermediate `capture.json` file is a JSON array of `crawl.ObservedRequest` structs. Each entry contains method, URL, headers, body, and response data. This format is shared between crawl output, importer output, and generator input.

## CLI Commands

| Command   | Purpose |
|-----------|---------|
| `scan`    | Full pipeline: crawl + classify + probe + generate |
| `crawl`   | Capture traffic via headless browser → capture.json |
| `import`  | Convert Burp XML / HAR / mitmproxy → capture.json |
| `generate` | Produce spec from capture.json (REST→OpenAPI, GraphQL→SDL, WSDL→WSDL) |
| `version` | Show version information |

## Test Infrastructure

The `test/` directory contains live test targets:

- **test/rest-api/**: Go HTTP server exposing REST endpoints for end-to-end testing
- **test/soap-service/**: Go HTTP server exposing SOAP/WSDL endpoints
- **test/graphql-server/**: Node.js GraphQL server with Apollo

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

GitHub Actions runs on push to main and PRs: build, test (with 80% coverage threshold), lint (golangci-lint v2), and format check.
