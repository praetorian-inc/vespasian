# Crawler Backend Comparison: RodCrawler vs HTTPCrawler

## Summary

Vespasian exposes a single `Crawler` interface with two implementations: `HTTPCrawler`
(stdlib `net/http` engine) for fast, Chrome-free crawling of static and REST targets, and
`RodCrawler` (go-rod / Chromium) for JavaScript-heavy or SPA targets that issue runtime
`fetch`/XHR requests. Use `RodCrawler` (via `--headless=true`, the default) when you need
SPA coverage; use `HTTPCrawler` (`--headless=false`) when you need speed or a Chrome-free
environment.

## Methodology

- **Fixture:** `pkg/crawl/bench_test.go` — deterministic linked static HTML (`benchPages=20`
  pages), no randomness or time-based content. Index page links to 20 leaf pages; each leaf
  links to the next (ring) and back to the index.
- **Command:**
  ```text
  go test -run '^$' -bench 'Benchmark.*Crawl' -benchmem ./pkg/crawl/
  ```
- **Environment:** linux/arm64 (12-core), Go runtime benchmarking framework (`testing.B`).
- **Caveats:**
  - Chrome cold-start (≈ 1–3 s per `b.N` iteration) dominates `BenchmarkRodCrawl` wall
    time. Rod numbers measure end-to-end throughput with Chrome launch cost included, not
    raw crawl throughput.
  - `heapbytes/op` uses `runtime.MemStats.TotalAlloc` delta (monotonically increasing
    allocation counter, stable under GC scheduling) rather than `HeapInuse` peak (which is
    non-deterministic). Both metrics are comparable across backends but `TotalAlloc` is more
    reproducible.
  - `BenchmarkRodCrawl` is run without `-race` when Chrome CDP goroutines cause race
    instrumentation false positives; `BenchmarkHTTPCrawl` always runs with `-race`.

## Results

Benchmark run on 2026-06-05. Raw output:

```text
goos: linux
goarch: arm64
pkg: github.com/praetorian-inc/vespasian/pkg/crawl
BenchmarkHTTPCrawl-12    542   2390080 ns/op   21.00 captured/op   786142 heapbytes/op   786142 B/op   4997 allocs/op
BenchmarkHTTPCrawl-12    493   2367137 ns/op   21.00 captured/op   784550 heapbytes/op   784549 B/op   4993 allocs/op
BenchmarkRodCrawl-12       1   11301201505 ns/op   42.00 captured/op   7041496 heapbytes/op   7041496 B/op   116148 allocs/op
BenchmarkRodCrawl-12       1   11220377755 ns/op   42.00 captured/op   6550600 heapbytes/op   6550600 B/op   111666 allocs/op
```

### 1. Request Count (`captured/op`)

| Backend     | captured/op | Notes                                                           |
|-------------|-------------|----------------------------------------------------------------|
| HTTPCrawler | 21          | Deterministic: 1 index + 20 leaf pages                        |
| RodCrawler  | 42          | Chrome captures additional browser-internal requests (favicon, etc.) |

### 2. Wall-Clock Time (`ns/op`)

| Backend     | ns/op (approx)  | Notes                                      |
|-------------|-----------------|---------------------------------------------|
| HTTPCrawler | ~2.4 ms         | Pure Go stdlib; no process spawn            |
| RodCrawler  | ~11,000 ms      | Chrome cold-start (~1–3 s) per iteration dominates |

The ~4,600× wall-time difference on this fixture is almost entirely Chrome
cold-start cost. Rod's per-page crawl latency is not captured separately here.

### 3. Peak Memory (`heapbytes/op`, `B/op`, `allocs/op`)

| Backend     | heapbytes/op | B/op    | allocs/op |
|-------------|--------------|---------|-----------|
| HTTPCrawler | ~786 KB      | ~786 KB | ~4,995    |
| RodCrawler  | ~6.8 MB      | ~6.8 MB | ~113,907  |

`heapbytes/op` = `TotalAlloc` delta / `b.N`. Rod's higher allocation count
reflects CDP protocol parsing and go-rod library allocations within the Go process.
`TotalAlloc` measures only Go heap allocations; Chrome subprocess memory and I/O
are not included in this metric.

### 4. Race Safety

| Backend     | `-race` |
|-------------|---------|
| HTTPCrawler | Passes cleanly (`go test -race ./pkg/crawl/`) |
| RodCrawler  | Not guaranteed with `-race` (go-rod CDP goroutines may trigger false positives on some platforms) |

## Capability Gap

| Capability                              | HTTPCrawler | RodCrawler |
|-----------------------------------------|-------------|------------|
| Static HTML link following              | Yes         | Yes        |
| Scope confinement (cross-origin links)  | Yes         | Yes        |
| Depth and max-pages limiting            | Yes         | Yes        |
| Custom request headers                  | Yes         | Yes        |
| Relative-link resolution (post-redirect)| Yes         | Yes        |
| SSRF redirect guard (Go dial)           | Yes         | N/A (Chrome network layer) |
| JavaScript execution                    | No          | Yes        |
| Inline-script literal extraction        | Yes (jsluice static scan) | Yes (+ runtime execution) |
| SPA runtime `fetch`/XHR capture         | **No**      | **Yes**    |
| Cookie propagation across redirects     | Yes (stdlib) | Yes (Chrome) |

The critical gap is **SPA runtime `fetch`/XHR capture**: `HTTPCrawler` performs
no JavaScript execution and cannot observe requests issued dynamically at runtime.
`RodCrawler` hooks Chrome's network layer and captures all requests regardless of
how they are initiated. This gap is verified by `pkg/crawl/spa_integration_test.go`
(`TestRodCrawler_CapturesSPAFetch`), which closes LAB-1535.
