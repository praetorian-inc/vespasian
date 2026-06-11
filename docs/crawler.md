# Crawler

`pkg/crawl` is the capture stage of the vespasian pipeline. It produces
`[]ObservedRequest` values that are written to `capture.json` and consumed
by the classify/probe/generate stages.

## Overview

The capture stage exposes a single seam: the `Crawler` interface. A caller
obtains an implementation via `NewCrawler(opts)`, which inspects
`opts.Headless` to select the backend. Both backends produce identical
`[]ObservedRequest` output — the choice of backend is invisible to the rest
of the pipeline.

## The Crawler interface and factory

**`pkg/crawl/crawler.go`**

```go
// Crawler is the interface for web crawling to capture HTTP traffic.
// There are two implementations: RodCrawler (headless go-rod engine) and
// HTTPCrawler (stdlib net/http engine).
type Crawler interface {
    Crawl(ctx context.Context, targetURL string) ([]ObservedRequest, error)
}

// NewCrawler creates a new crawler with the given options.
// When opts.Headless is true, it returns a RodCrawler (headless go-rod engine).
// Otherwise it returns an HTTPCrawler (stdlib net/http engine).
func NewCrawler(opts CrawlerOptions) Crawler {
    if opts.Headless {
        return &RodCrawler{opts: opts}
    }
    return &HTTPCrawler{opts: opts}
}
```

`NewCrawler` is the recommended constructor: it selects the backend from
`opts.Headless`. Option defaults (e.g. `MaxPages`, `Concurrency`) and input
validation are applied at the start of `Crawl` — via `validateCrawlInputs` and
`clampConcurrency` — not in `NewCrawler`.

## Backends

| Backend | CLI flag | Engine | JS execution | Chrome required | Notable characteristics |
|---------|----------|--------|-------------|-----------------|------------------------|
| `RodCrawler` | `--headless` (default `true`) | go-rod driving Chrome via CDP | Yes | Yes | Concurrent tabs; all XHR/fetch/dynamically-constructed requests captured via CDP network listeners |
| `HTTPCrawler` | `--headless=false` | stdlib `net/http` | No | No | DFS frontier, 150 rps rate limiter, 10 MB per-page body cap, inline `<script>` analysis via jsluice |

**When to use each:**

- Use `RodCrawler` (the default) for single-page applications, React/Vue/Angular
  frontends, or any site that makes API calls from JavaScript. Chrome's network
  stack intercepts every outbound request regardless of how it was constructed.
- Use `HTTPCrawler` (`--headless=false`) for static or server-rendered sites
  where JavaScript is not the primary driver of API calls, for CI pipelines
  where Chrome is unavailable, or when you need a lightweight dependency-free
  crawl.

## Options

`CrawlerOptions` fields and their CLI counterparts (`cmd/vespasian/main.go`,
`CrawlOptions` struct):

| Field | Type | Default | CLI flag | Description |
|-------|------|---------|----------|-------------|
| `Headless` | `bool` | `true` | `--headless` | Selects backend: `true` → `RodCrawler`, `false` → `HTTPCrawler` |
| `Depth` | `int` | `3` | `--depth` | Maximum crawl depth (hops from seed) |
| `MaxPages` | `int` | `100` | `--max-pages` | Maximum pages to crawl; 0 uses `DefaultMaxPages` (1000) |
| `Timeout` | `time.Duration` | `10m` | `--timeout` | Wall-clock limit for the entire crawl |
| `Scope` | `string` | `"same-origin"` | `--scope` | `"same-origin"` or `"same-domain"` |
| `Proxy` | `string` | — | `--proxy` | HTTP/HTTPS proxy for Chrome (headless only) |
| `Concurrency` | `int` | `10` | `--concurrency` | Parallel browser tabs (headless) or HTTP workers (non-headless); 0 maps to `DefaultConcurrency` (10), capped at `MaxConcurrency` (50) |
| `AllowPrivate` | `bool` | `false` | `--dangerous-allow-private` | Disables SSRF protection; required when the seed URL is itself a private host |
| `Headers` | `map[string]string` | — | `-H` | Custom request headers injected on every fetch |
| `BrowserMgr` | `*BrowserManager` | `nil` | — | Caller-owned Chrome instance; required for force-exit (second SIGINT) support |
| `Stderr` | `io.Writer` | `nil` | — | Receives status messages; `nil` silences output |

**Constants** (package `crawl`):

| Constant | Value | Purpose |
|----------|-------|---------|
| `DefaultMaxPages` | 1000 | Used when `MaxPages ≤ 0` |
| `MaxResponseBodySize` | 1 MB | Retention cap applied to stored response bodies |
| `PageTimeout` | 30 s | Per-page timeout for both backends |
| `MaxHTTPBodySize` | 10 MB | Read cap per HTTP response in `HTTPCrawler` (DoS guard) |
| `DefaultConcurrency` | 10 | Worker/tab count when `Concurrency` is 0 |
| `MaxConcurrency` | 50 | Upper bound on worker/tab count |

## Capability gap

The `HTTPCrawler` does not execute JavaScript. It parses HTML (goquery) and
static inline `<script>` blocks (jsluice), but it cannot observe requests that
are constructed at runtime — for example, an inline `fetch('/graphql')` call
that only executes after user interaction or a framework's boot sequence.
`RodCrawler` captures those requests because Chrome intercepts all outbound
traffic via CDP network listeners.

For a quantitative comparison of endpoint coverage between the two backends,
see [benchmarks/crawler-comparison.md](benchmarks/crawler-comparison.md).

## SSRF model

Both backends share `scopeChecker` (`pkg/crawl/scope.go`), which accepts or
rejects a URL based on the configured scope policy and the
`--dangerous-allow-private` flag.

The two backends differ in **where** the final DNS-rebinding TOCTOU protection
is applied:

**`HTTPCrawler` path** — authoritative dial-time pin via `ssrfSafeDialContext`
(`pkg/crawl/scope.go` → `ssrf.SafeDialContext`). The transport
for `newHTTPClient` is cloned from `http.DefaultTransport` with `DialContext`
replaced. At connect time, `SafeDialContext` re-resolves the host via DNS
and rejects the connection if any returned IP is private (see
`pkg/ssrf/ssrf.go`). This closes the DNS-rebinding TOCTOU window: a
domain could resolve to a public IP during the upfront scope check and
re-resolve to `127.0.0.1` or `169.254.169.254` by the time the dialer
connects. The `redirectScopeGuard` (`http_crawler.go`) provides a second
defense-in-depth layer at the redirect-follow level.

**`RodCrawler` path** — relies on `scopeChecker` for the upfront SSRF check
and on Chrome's own networking stack for all subsequent DNS resolution. Go's
`ssrfSafeDialContext` is not wired into Chrome; Chrome-resolved addresses are
not re-validated at dial time. This is a known limitation documented in
`rod_crawler.go` and `doc.go`.

When `AllowPrivate` is `true`, `newHTTPClient` uses `http.DefaultTransport`
unchanged (no dial-time pin) and `scopeChecker` bypasses the private-IP
check, permitting crawls of RFC1918 and loopback targets.

## Adding a backend

1. Implement the `Crawler` interface — one method:

```go
type MyBackend struct { opts CrawlerOptions }

func (b *MyBackend) Crawl(ctx context.Context, targetURL string) ([]ObservedRequest, error) {
    maxPages, err := validateCrawlInputs(b.opts, targetURL)
    if err != nil {
        return nil, err
    }
    scopeFn, err := scopeChecker(targetURL, b.opts.Scope, b.opts.AllowPrivate)
    if err != nil {
        return nil, fmt.Errorf("scope setup: %w", err)
    }
    // ... backend-specific crawl logic
}
```

2. Add a branch in `NewCrawler` (`crawler.go`):

```go
func NewCrawler(opts CrawlerOptions) Crawler {
    switch {
    case opts.Headless:
        return &RodCrawler{opts: opts}
    case opts.MyCondition:
        return &MyBackend{opts: opts}
    default:
        return &HTTPCrawler{opts: opts}
    }
}
```

3. Reuse the shared helpers:
   - `scopeChecker` — scope + SSRF upfront check (required)
   - `validateCrawlInputs` — input validation and `maxPages` resolution (required)
   - `ssrf.SafeDialContext` — dial-time IP pin (HTTP-based backends)
   - `newURLFrontier` — DFS/BFS URL queue with depth tracking

4. Register the backend in the parameterized contract suite
   (`pkg/crawl/contract_test.go`, `crawlerBackends()`). The suite runs
   `TestCrawlerContract_FollowsLinks`, `TestCrawlerContract_RespectsMaxPages`,
   `TestCrawlerContract_SendsCustomHeaders`, `TestCrawlerContract_ScopeConfinement`,
   `TestCrawlerContract_RelativeLinksResolvedAgainstFinalURL`, and
   `TestCrawlerContract_DepthLimit` against every registered backend:

```go
func crawlerBackends() []crawlerContractCase {
    return []crawlerContractCase{
        {name: "http", headless: false},
        {name: "rod",  headless: true},
        {name: "my-backend", headless: false}, // add your row here
    }
}
```

   If the backend requires a runtime dependency (like Chrome for `RodCrawler`),
   add a `skipIfNoX(t)` guard analogous to `skipIfNoChrome`.
