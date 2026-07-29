# Contributing to Vespasian

Thanks for your interest in contributing. This doc covers the dev setup, project structure, and how to add a classifier, generator, importer, or probe strategy.

For what Vespasian is and how the two-stage pipeline fits together, read the [Architecture](README.md#architecture) section of the README first — this guide assumes it.

## Table of contents

- [Code of conduct](#code-of-conduct)
- [Getting started](#getting-started)
- [Development setup](#development-setup)
- [Project layout](#project-layout)
- [Adding a classifier](#adding-a-classifier)
- [Adding a generator](#adding-a-generator)
- [Adding an importer](#adding-an-importer)
- [Adding a probe strategy](#adding-a-probe-strategy)
- [Testing](#testing)
- [Code style](#code-style)
- [Commit messages](#commit-messages)
- [Pull requests](#pull-requests)
- [Reporting issues](#reporting-issues)
- [Security disclosures](#security-disclosures)

## Code of conduct

This project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you're expected to uphold it. Report unacceptable behavior to security@praetorian.com.

## Getting started

1. Fork the repository on GitHub.
2. Clone your fork locally:

```bash
git clone git@github.com:<your-username>/vespasian.git
cd vespasian
```

3. Add the upstream remote:

```bash
git remote add upstream git@github.com:praetorian-inc/vespasian.git
```

4. Create a feature branch:

```bash
git checkout -b feat/my-change
```

No CLA or DCO sign-off is required to contribute.

## Development setup

### Prerequisites

- **Go 1.25.8+** — the version in `go.mod` is the source of truth, and CI reads it from there
- **golangci-lint v2.12.2** — pin this version to match CI:
  ```bash
  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
  ```
- **CGO enabled** (`CGO_ENABLED=1`) — CI builds with it, so keep it on locally
- **A real Chrome/Chromium** — only needed for headless crawling and the live test suite, not for unit tests

### Build and run

```bash
make deps             # go mod download && go mod tidy
make build            # Build to bin/vespasian
make test             # go test -race ./...
make fmt              # gofmt -s -w .
make vet              # go vet ./...
make lint             # golangci-lint run
make check            # fmt + vet + lint + test — run this before opening a PR
make coverage         # Coverage profile + per-function report (excludes test/)
make live-test-clean  # Stop orphaned live-test services
```

Note that `make check` runs `make fmt` first, which rewrites files in place via `gofmt -s -w .` — it validates *and* reformats. Expect it to modify your working tree, and check `git status` afterwards so any reformatting lands in your commit rather than surprising you later. Use `make vet lint test` if you want the checks without the rewrite.

### Devcontainers

Unit tests run fine in a container. Two gotchas if you develop in one:

- The **live test suite** reaches its targets at `http://${TEST_HOST:-localhost}:<port>`. If the harness runs in a container while the target services run on the Docker host, set `TEST_HOST` (e.g. `TEST_HOST=host.docker.internal`). Without it, `localhost` resolves to the container's own loopback, the crawler connects to nothing, and captures come back empty. Note that `setup-live-targets.sh` does *not* read `TEST_HOST` — run it on the host that actually runs the target binaries.
- A **snap-packaged Chromium stub won't work** for browser-driven tests; you need a real Chromium binary.

See [`test/README.md`](test/README.md) for details.

## Project layout

```text
cmd/
  vespasian/            CLI entry point (Kong), commands, signal handling, browser lifecycle

internal/
  pipeline/             Shared crawl/classify/probe/generate orchestration used by
                        both the CLI and the SDK. API-type detection and the
                        classifier/strategy wiring live here
  grpcwire/             gRPC length-prefixed framing + protobuf wire parser
  tnetenc/              tnetstring codec for mitmproxy's native format

pkg/
  crawl/                Two crawler backends (go-rod headless, net/http), capture
                        file I/O, ObservedRequest, JS-replay
  ssrf/                 SSRF protection: URL validation + connect-time re-resolution
                        to defeat DNS rebinding
  analyze/              Static analysis of captured HTML (form extraction)
    jsstatic/           Static analysis of captured JS bundles via jsluice
  classify/             Classification engine and per-type classifiers
                        (REST, GraphQL, WSDL, gRPC), deduplication
  probe/                Active endpoint probing strategies
  generate/             Spec generation interface + registry
    rest/               OpenAPI 3.0
    graphql/            GraphQL SDL
    wsdl/               WSDL
    grpc/               .proto (proto3)
  importer/             Burp XML / HAR / mitmproxy importers + registry
  mediatype/            Shared media-type canonicalization
  sdk/                  capability-sdk integration for Chariot/Guard hosts

docs/                   Additional documentation
test/                   Live test targets and harness (see test/README.md)
```

Package-level documentation lives in `doc.go` files. If your change alters a package's public API or purpose, update its `doc.go`.

## Adding a classifier

Classifiers decide whether an observed request is an API call, and how confident that judgment is. Implement `APIClassifier` from [`pkg/classify/classifier.go`](pkg/classify/classifier.go):

```go
type APIClassifier interface {
    // Name returns the classifier name (e.g., "rest", "graphql").
    Name() string

    // Classify returns whether the request is an API call and the confidence score.
    Classify(req crawl.ObservedRequest) (bool, float64)
}
```

1. Create `pkg/classify/<name>_classifier.go` (lowercase with underscores).
2. Return a confidence in `[0.0, 1.0]`. `RunClassifiers` keeps the highest-confidence match above the caller's threshold, so calibrate honestly — an over-confident classifier will shadow a correct one.
3. Wire it into `ClassifiersForType` in [`internal/pipeline/apitype.go`](internal/pipeline/apitype.go), which maps an API type to its classifiers.
4. If the type should be **auto-detected**, also add it to `DetectAPIType`. Not every type belongs there — gRPC is deliberately excluded because its binary HTTP/2 framing isn't reliably detectable, so it requires an explicit `--api-type grpc`.
5. Add `<name>_classifier_test.go` with table-driven cases covering both positive and negative classification. False positives matter as much as misses here.

## Adding a generator

Generators turn classified endpoints into a specification document. Implement `SpecGenerator` from [`pkg/generate/generator.go`](pkg/generate/generator.go):

```go
type SpecGenerator interface {
    // APIType returns the API type this generator supports (e.g., "rest", "graphql").
    APIType() string

    // Generate produces an API specification from the endpoints.
    Generate(endpoints []classify.ClassifiedRequest) ([]byte, error)

    // DefaultExtension returns the default file extension for the generated spec.
    DefaultExtension() string
}
```

1. Create a sub-package under `pkg/generate/<apitype>/`.
2. Add a `case` to the switch in `GetWithOptions` in [`pkg/generate/registry.go`](pkg/generate/registry.go), and extend the "supported" list in its error message. Registration is explicit — there is no `init()` hook.
3. If your generator needs tunable behavior, add a field to the `Options` struct rather than a package-level global, so the CLI and SDK configure it the same way.
4. Emit **deterministic** output — sort collections before rendering. Non-deterministic specs make diffs and golden-file tests useless.
5. Add tests that assert on the generated document, not just that generation returned no error. Where the format has a validator, validate the output.

## Adding an importer

Importers convert an external traffic format into `[]crawl.ObservedRequest`. Implement `TrafficImporter` from [`pkg/importer/importer.go`](pkg/importer/importer.go):

```go
type TrafficImporter interface {
    // Name returns the importer name (e.g., "burp", "har").
    Name() string

    // Import reads external traffic and converts it to ObservedRequest format.
    Import(r io.Reader) ([]crawl.ObservedRequest, error)
}
```

1. Create `pkg/importer/<format>_importer.go`.
2. Add an entry to the `registry` map in [`pkg/importer/registry.go`](pkg/importer/registry.go).
3. **Respect the safety caps.** Importers parse untrusted, attacker-adjacent input, so the package enforces layered limits — 500 MB per file, 64 MB per tnetstring element, 1 M entries per list/dict, 500 K flows per native stream. A new importer must enforce equivalent bounds; unbounded allocation driven by input is a security bug, not a performance nit.
4. Add fixtures under `test/fixtures/` and cover malformed, truncated, and oversized input alongside the happy path.

## Adding a probe strategy

Probe strategies actively enrich classified endpoints. Implement `ProbeStrategy` from [`pkg/probe/prober.go`](pkg/probe/prober.go):

```go
type ProbeStrategy interface {
    // Name returns the strategy name (e.g., "options", "schema").
    Name() string

    // Probe enriches the classified requests with additional data.
    Probe(ctx context.Context, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error)
}
```

Register it in `StrategiesForType` in [`internal/pipeline/apitype.go`](internal/pipeline/apitype.go). Where several strategies target one API type, order matters — richer techniques run first and later ones must not overwrite their results.

Requirements:

- **Honor `ctx`.** Every network call must be cancellable; probes run against live targets under a user-controlled timeout.
- **Go through `pkg/ssrf`.** Probes take their target from crawled traffic, which is attacker-influenced. Don't hand-roll host validation, and use the injectable dialer rather than a bare `net.Dial`.
- **Keep request volume low.** Probes multiply across every discovered endpoint.
- **Degrade gracefully.** A probe that can't reach its target should return the endpoints it was given plus a recorded `ProbeError`, not fail the whole run.

## Testing

### Unit tests

```bash
make test                                          # Everything, with the race detector
go test ./pkg/classify/...                         # One package
go test -run TestFunctionName ./pkg/classify/...   # One test
```

Conventions:

- Test files mirror source files: `foo.go` → `foo_test.go`.
- Table-driven tests with descriptive subtest names.
- Tests run under `-race` in CI. Don't introduce shared mutable global state.

### Coverage

```bash
make coverage    # Writes coverage.out, prints per-function coverage
```

Aim to keep coverage at or above **80%** for the packages you touch. CI measures coverage on every Go PR but does not currently fail a build below a threshold, so this is enforced at review time — a PR that materially drops coverage will be asked for tests.

### Live tests

`test/` contains real servers (REST, SOAP/WSDL, GraphQL, gRPC) plus SPA and JS-static fixtures that the end-to-end suite exercises:

```bash
./test/setup-live-targets.sh           # Start the target services
./test/run-live-tests.sh               # Run the suite
./test/run-live-tests.sh --targets rest-api    # One target
make live-test-clean                   # Stop services when you're done
```

Every live crawl targets localhost, which Vespasian's SSRF protection blocks by default — the harness passes `--dangerous-allow-private` for that reason. If you reproduce a single test by hand, you need the flag too.

The live suite also runs in CI on every PR. If a change genuinely cannot affect it, a maintainer can apply the `skip-live-tests` label to skip that job; pushes to `main` always run it.

See [`test/README.md`](test/README.md) for options, expected results, and troubleshooting.

## Code style

### Formatting and linting

All code must pass `golangci-lint` (config in [`.golangci.yml`](.golangci.yml)). Enabled linters:

| Linter | Checks |
|--------|--------|
| `gocritic` | Opinionated correctness and style diagnostics |
| `gocyclo` | Cyclomatic complexity, max **15** |
| `gosec` | Common security mistakes |
| `misspell` | Spelling (US locale) |
| `revive` | Exported-symbol documentation, including private receivers |

`errcheck` runs with `check-type-assertions` and `check-blank` enabled, so unchecked type assertions and `_ =` discards of errors are failures. Formatting is `gofmt` plus `goimports` with `github.com/praetorian-inc/vespasian` as the local prefix, so project imports group last. Test files are exempt from `errcheck` and `gocyclo`.

Run `make check` before submitting.

### Guidelines

- **Go file naming: lowercase with underscores** — `rest_classifier.go`, not `restClassifier.go`.
- Keep functions under complexity 15. If the linter complains, split the function rather than suppressing it.
- Add a `//nolint` directive only with a comment explaining why, and expect it to be questioned in review.
- Use `context.Context` for cancellation in all I/O paths.
- Check every error. Return `(result, error)` rather than panicking.
- Every source file carries the Apache 2.0 license header. Copy it from an existing file into new ones.

## Commit messages

This project uses **conventional commits**. Prefix each commit with its type:

| Prefix | Use for |
|--------|---------|
| `feat:` | New features |
| `fix:` | Bug fixes |
| `test:` | Adding or updating tests |
| `refactor:` | Restructuring without behavior change |
| `docs:` | Documentation changes |
| `ci:` | CI workflow and pipeline changes |
| `deps:` | Dependency updates |
| `chore:` | Build and tooling changes |

An optional scope narrows it: `fix(test):`, `feat(crawl):`. Use the imperative mood, and put the "why" in the body when the diff doesn't make it obvious. Reference the tracking issue where there is one.

```text
feat(importer): support mitmproxy native tnetstring format

fix(generate): stop collapsing distinct routes sharing a path prefix

test: add live coverage for HTML form extraction
```

## Pull requests

1. **One logical change per PR.** If you're fixing a bug and adding a feature, split them.
2. `make check` must pass.
3. Describe what changed and why, and link the related issue.
4. Add tests for new behavior.
5. Keep diffs reviewable — no unrelated reformatting.
6. Update `README.md` and the relevant `doc.go` if you change user-facing behavior or a package's public API.

Review is driven by [`CODEOWNERS`](CODEOWNERS); a maintainer review is required before merge.

Two CI workflows gate a PR:

- **CI** — build, test, lint, and format check. Runs only when a PR touches Go sources, `go.mod`, `go.sum`, `.golangci*`, or the `Makefile`, so docs-only PRs intentionally show no CI run.
- **Live Tests** — the end-to-end suite, on every PR.

### PR checklist

- [ ] `make check` passes (fmt, vet, lint, test)
- [ ] Tests added or updated for the change
- [ ] New classifier / generator / importer / probe registered where the pipeline expects it
- [ ] Commit messages follow conventional commit format
- [ ] Apache 2.0 license header on any new source file
- [ ] `README.md` / `doc.go` updated if user-facing behavior or a public API changed

## Reporting issues

Open a GitHub issue and include:

- What you expected versus what happened
- Steps to reproduce — the CLI command and flags, and the capture source (crawl, Burp XML, HAR, mitmproxy)
- Vespasian version (`vespasian version`)
- Go version (`go version`), OS, and architecture
- A **redacted** `capture.json` excerpt where relevant

Captures and generated specs routinely contain hostnames, tokens, cookies, and request bodies from real targets. Redact before attaching anything to a public issue.

Use issues for questions too, until dedicated discussion channels exist.

## Security disclosures

**Do not open a public issue for a security vulnerability.** Follow [`SECURITY.md`](SECURITY.md) — email security@praetorian.com.
