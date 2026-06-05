// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// benchPages is the fixed page count for the deterministic benchmark fixture.
// Kept small to bound Chrome cold-start cost for BenchmarkRodCrawl.
const benchPages = 20

// newBenchFixture serves a fixed tree of inter-linked static pages: an index
// page linking to pages /p0../p(N-1), each page linking to the next (modulo N)
// and back to the index. Counts are deterministic (no time/random content) so
// captured-request counts match across runs and backends.
func newBenchFixture(pages int) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		for i := range pages {
			fmt.Fprintf(&b, `<a href="/p%d">p%d</a>`, i, i)
		}
		fmt.Fprintf(w, "<html><body>%s</body></html>", b.String())
	})
	for i := range pages {
		mux.HandleFunc(fmt.Sprintf("/p%d", i), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body><a href="/p%d">next</a></body></html>`, (i+1)%pages)
		})
	}
	return httptest.NewServer(mux)
}

// probeChromeForBench performs a one-shot Chrome availability check for use
// by BenchmarkRodCrawl. It reuses the same NewBrowserManager launch probe as
// the contract gate (skipIfNoChrome) but returns an error rather than calling
// t.Skip so benchmark callers can use b.Skip.
func probeChromeForBench() error {
	bm, err := NewBrowserManager(BrowserOptions{Headless: true})
	if err != nil {
		return err
	}
	bm.Close()
	return nil
}

// BenchmarkHTTPCrawl measures the stdlib net/http crawler against the
// deterministic linked-HTML fixture. Reports ns/op, B/op, allocs/op (standard
// -benchmem), captured/op (request count), and heapbytes/op (TotalAlloc delta
// via runtime.MemStats — a stable, GC-independent allocation signal).
func BenchmarkHTTPCrawl(b *testing.B) {
	srv := newBenchFixture(benchPages)
	defer srv.Close()
	benchCrawl(b, srv, false)
}

// BenchmarkRodCrawl measures the go-rod headless crawler against the same
// deterministic fixture. Skips when Chrome is unavailable.
//
// Each iteration relaunches Chrome, so b.N effectively stays at 1 and ns/op is
// a single cold-start sample (~1-3 s) dominated by Chrome launch overhead. Use
// these numbers for RELATIVE comparison vs BenchmarkHTTPCrawl, not as absolute
// per-page latency measurements. A shared BrowserMgr optimisation is deferred.
//
// Note: run without -race when Chrome+race proves flaky in your environment
// (go-rod spawns CDP goroutines; race instrumentation can cause false positives
// on the CDP goroutines communicating with Chrome). HTTP benchmark always runs with -race.
func BenchmarkRodCrawl(b *testing.B) {
	if err := probeChromeForBench(); err != nil {
		b.Skipf("Chrome unavailable: %v", err)
	}
	srv := newBenchFixture(benchPages)
	defer srv.Close()
	benchCrawl(b, srv, true)
}

// benchCrawl is the shared benchmark body. It measures wall-clock (b.N loop),
// allocations (b.ReportAllocs), captured-request count (captured/op custom
// metric), and total heap allocations (heapbytes/op via runtime.MemStats
// TotalAlloc delta).
//
// Race-free: each iteration builds a fresh NewCrawler; Crawl is internally
// synchronized (http_crawler.go mu; engine.go mu) and returns a snapshot copy.
// The fixture handlers are stateless — no shared mutable state across
// iterations.
//
// TotalAlloc is used (not HeapInuse peak) because HeapInuse is non-deterministic
// under GC scheduling. TotalAlloc is a monotonically increasing counter giving a
// stable, comparable allocation signal across runs and backends.
func benchCrawl(b *testing.B, srv *httptest.Server, headless bool) {
	b.Helper()
	b.ReportAllocs()
	opts := CrawlerOptions{
		Depth:        3,
		MaxPages:     1000,
		Timeout:      60 * time.Second,
		Scope:        "same-origin",
		AllowPrivate: true,
		Headless:     headless,
	}

	var lastCount int
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		got, err := NewCrawler(opts).Crawl(context.Background(), srv.URL)
		if err != nil {
			b.Fatalf("crawl: %v", err)
		}
		lastCount = len(got)
	}

	b.StopTimer()
	runtime.ReadMemStats(&m1)

	// lastCount == every-iteration count: fixture is deterministic, so the
	// per-iteration captured count is constant (using last is equivalent to first).
	b.ReportMetric(float64(lastCount), "captured/op")
	b.ReportMetric(float64(m1.TotalAlloc-m0.TotalAlloc)/float64(b.N), "heapbytes/op")
}
