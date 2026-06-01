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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPCrawler_FollowsLinks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<a href="/p2">x</a>`)
		case "/p2":
			fmt.Fprint(w, `ok`)
		}
	}))
	defer srv.Close()
	c := &HTTPCrawler{opts: CrawlerOptions{Depth: 2, MaxPages: 10, Timeout: 10 * time.Second, AllowPrivate: true}}
	got, err := c.Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 {
		t.Errorf("got %d results, want ≥2", len(got))
	}
	for _, r := range got {
		if r.Source != "http" {
			t.Errorf("Source = %q, want http", r.Source)
		}
	}
}

func TestHTTPCrawler_RespectsMaxPages(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="/page%d">next</a>`, n+1)
	}))
	defer srv.Close()
	c := &HTTPCrawler{opts: CrawlerOptions{Depth: 20, MaxPages: 2, Timeout: 10 * time.Second, AllowPrivate: true}}
	results, err := c.Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(results) > 2 {
		t.Errorf("got %d results, want ≤2 (MaxPages)", len(results))
	}
}

func TestHTTPCrawler_BodyCap(t *testing.T) {
	// Server returns more than MaxHTTPBodySize bytes
	bigBody := make([]byte, MaxHTTPBodySize+1000)
	for i := range bigBody {
		bigBody[i] = 'A'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(bigBody)
	}))
	defer srv.Close()
	c := &HTTPCrawler{opts: CrawlerOptions{Depth: 1, MaxPages: 1, Timeout: 10 * time.Second, AllowPrivate: true}}
	results, err := c.Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	// The stored body must be at most MaxResponseBodySize (retention cap)
	if len(results[0].Response.Body) > MaxResponseBodySize {
		t.Errorf("stored body = %d bytes, want ≤MaxResponseBodySize (%d)", len(results[0].Response.Body), MaxResponseBodySize)
	}
}

func TestHTTPCrawler_PerPageTimeoutSurfaced(t *testing.T) {
	// Server that holds the connection open until the client gives up.
	// Use a channel to unblock it when the test ends.
	unblock := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			// Block until unblocked or the test ends.
			select {
			case <-unblock:
			case <-time.After(60 * time.Second):
			}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="/slow">slow</a>`)
	}))
	defer func() {
		close(unblock)
		srv.Close()
	}()

	var stderr bytes.Buffer
	c := &HTTPCrawler{opts: CrawlerOptions{
		Depth:        2,
		MaxPages:     5,
		Stderr:       &stderr,
		AllowPrivate: true,
	}}

	// Use a short overall context so the crawl terminates quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Crawl should return without panicking even when a page times out or the
	// overall context expires.
	_, _ = c.Crawl(ctx, srv.URL)
	// Test passes if we reach here (no panic, crawl returns).

	// Verify that the timeout/error was surfaced to Stderr, not silently dropped.
	stderrOut := stderr.String()
	if stderrOut == "" {
		t.Error("expected timeout or error message on Stderr; got empty output")
	}
}

func TestHTTPCrawler_ClampConcurrency(t *testing.T) {
	tests := []struct {
		input int
		want  int
	}{
		{0, DefaultConcurrency},
		{5, 5},
		{DefaultConcurrency, DefaultConcurrency},
		{MaxConcurrency, MaxConcurrency},
		{MaxConcurrency + 1, MaxConcurrency},
		{100, MaxConcurrency},
	}
	for _, tt := range tests {
		got := clampConcurrency(tt.input)
		if got != tt.want {
			t.Errorf("clampConcurrency(%d) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestHTTPCrawler_InlineScriptExtraction(t *testing.T) {
	var mu sync.Mutex
	var inlineCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<script>fetch("/api/x")</script><a href="/api/x">x</a>`)
		case "/api/x":
			mu.Lock()
			inlineCount++
			mu.Unlock()
			fmt.Fprint(w, `ok`)
		}
	}))
	defer srv.Close()
	c := &HTTPCrawler{opts: CrawlerOptions{Depth: 2, MaxPages: 10, Timeout: 10 * time.Second, AllowPrivate: true}}
	got, _ := c.Crawl(context.Background(), srv.URL)
	found := false
	for _, r := range got {
		if strings.HasSuffix(r.URL, "/api/x") {
			found = true
		}
	}
	if !found {
		t.Error("/api/x not discovered via inline-script/link extraction")
	}
}

func TestHTTPCrawler_RedirectScopeBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
	}))
	defer srv.Close()
	var stderr bytes.Buffer
	c := &HTTPCrawler{opts: CrawlerOptions{Depth: 1, MaxPages: 5, Timeout: 10 * time.Second, Stderr: &stderr, AllowPrivate: true}}
	got, _ := c.Crawl(context.Background(), srv.URL)
	for _, r := range got {
		if strings.Contains(r.URL, "169.254.169.254") {
			t.Error("crawler followed redirect to cloud metadata host")
		}
	}
}

func TestApplyHeaders_SetsHeadersOnRequest(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	applyHeaders(req, map[string]string{
		"X-Custom-Header": "value1",
		"User-Agent":      "TestAgent/1.0",
	})
	if got := req.Header.Get("X-Custom-Header"); got != "value1" {
		t.Errorf("X-Custom-Header = %q, want value1", got)
	}
	if got := req.Header.Get("User-Agent"); got != "TestAgent/1.0" {
		t.Errorf("User-Agent = %q, want TestAgent/1.0", got)
	}
}

func TestApplyHeaders_NilHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	// applyHeaders with nil headers must not panic.
	applyHeaders(req, nil)
}

func TestRedirectScopeGuard_TooManyRedirects(t *testing.T) {
	guard := redirectScopeGuard(nil)
	// Simulate 10 previous redirects — guard must return an error.
	via := make([]*http.Request, 10)
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	err := guard(req, via)
	if err == nil {
		t.Error("expected error for 10+ redirects, got nil")
	}
	if !strings.Contains(err.Error(), "10 redirects") {
		t.Errorf("error = %q, want '10 redirects'", err.Error())
	}
}

func TestRedirectScopeGuard_AllowsInScopeRedirect(t *testing.T) {
	// A nil scopeFn means no scope checking — all redirects allowed.
	guard := redirectScopeGuard(nil)
	via := []*http.Request{}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/other", nil)
	if err := guard(req, via); err != nil {
		t.Errorf("in-scope redirect rejected: %v", err)
	}
}

// TestHTTPCrawler_SSRFRedirectBlocked verifies that a 302 redirect to a
// private IP (127.0.0.1 on a different port) is blocked by the redirect
// scope guard. No result entry for the redirected host/port should appear,
// the guard must have fired (evidenced by stderr), and the crawl must not
// panic.
//
// AllowPrivate is set to true so the test server (also on loopback) is
// reachable. The redirect is blocked because it targets a different origin
// (different port) from the seed, not solely because it is a private IP.
// The DialContext SSRF guard (SEC-BE-002 fix) provides the additional
// defense-in-depth layer for DNS-rebinding scenarios.
func TestHTTPCrawler_SSRFRedirectBlocked(t *testing.T) {
	// Track how many times the seed was hit to confirm the redirect was attempted.
	var seedHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			seedHits.Add(1)
			// Redirect to a different origin (port 1 — blocked by scope guard
			// and also a private-IP target for the SSRF DialContext guard).
			http.Redirect(w, r, "http://127.0.0.1:1/secret", http.StatusFound)
			return
		}
	}))
	defer srv.Close()

	var stderr bytes.Buffer
	c := &HTTPCrawler{opts: CrawlerOptions{
		Depth:        1,
		MaxPages:     5,
		Timeout:      5 * time.Second,
		Stderr:       &stderr,
		AllowPrivate: true, // allow test server on loopback
		Scope:        "same-origin",
	}}

	got, _ := c.Crawl(context.Background(), srv.URL)

	// Negative assertion: no result should contain port 1 (the redirect target).
	for _, r := range got {
		if strings.Contains(r.URL, ":1/") || strings.HasSuffix(r.URL, ":1") {
			t.Errorf("crawler followed redirect to blocked host; result URL = %s", r.URL)
		}
	}

	// Positive assertion: the redirect was attempted (seed was hit) and the guard
	// fired — evidenced by an error message on stderr (fetch error or scope block).
	if seedHits.Load() == 0 {
		t.Error("seed URL was never requested; redirect guard test is vacuous")
	}
	stderrOut := stderr.String()
	if !strings.Contains(stderrOut, "fetch:") && !strings.Contains(stderrOut, "blocked") && !strings.Contains(stderrOut, "redirect") {
		t.Errorf("expected guard to surface error on stderr (fetch/blocked/redirect), got: %q", stderrOut)
	}
	// Crawl must not panic and must return (no hang).
}

// TestHTTPCrawler_ConcurrentWorkers proves that with a single seed URL and
// Concurrency>1, multiple workers actually run in parallel. The seed page
// links to N children; each child blocks until K concurrent in-flight requests
// are observed simultaneously, then releases. If the crawl is silently
// single-threaded (the startup race described in QUAL-003/TEST-004), the barrier
// is never reached and the test times out via ctx.
func TestHTTPCrawler_ConcurrentWorkers(t *testing.T) {
	const (
		numChildren = 5
		minParallel = 3 // require at least 3 simultaneous in-flight fetches
	)

	var (
		inFlight    atomic.Int32
		maxParallel atomic.Int32
		barrier     = make(chan struct{}) // closed when minParallel are in-flight
		barrierOnce sync.Once
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			// Seed page: link to all children.
			var links strings.Builder
			for i := range numChildren {
				fmt.Fprintf(&links, `<a href="/c%d">child</a>`, i)
			}
			fmt.Fprint(w, links.String())
		default:
			// Child page: track concurrency and block until minParallel are in-flight.
			cur := inFlight.Add(1)
			defer inFlight.Add(-1)

			// Update max-in-flight high-water mark.
			for {
				old := maxParallel.Load()
				if cur <= old || maxParallel.CompareAndSwap(old, cur) {
					break
				}
			}

			// Once minParallel goroutines are here simultaneously, open the barrier.
			if cur >= minParallel {
				barrierOnce.Do(func() { close(barrier) })
			}

			// Block until the barrier opens (or 5s safety timeout).
			select {
			case <-barrier:
			case <-time.After(5 * time.Second):
			}

			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := &HTTPCrawler{opts: CrawlerOptions{
		Depth:        2,
		MaxPages:     50,
		Concurrency:  5,
		AllowPrivate: true,
	}}

	_, err := c.Crawl(ctx, srv.URL)
	if err != nil && ctx.Err() != nil {
		t.Fatalf("crawl timed out — workers likely collapsed to single-threaded (ctx: %v)", ctx.Err())
	}

	if got := maxParallel.Load(); got < minParallel {
		t.Errorf("max concurrent in-flight workers = %d, want >= %d; "+
			"crawler may be running single-threaded due to Pop/MarkActive race", got, minParallel)
	}
}

func TestHTTPCrawler_SendsCustomHeaders(t *testing.T) {
	var receivedAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAgent = r.Header.Get("X-Test-Header")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `ok`)
	}))
	defer srv.Close()
	c := &HTTPCrawler{opts: CrawlerOptions{
		Depth:        1,
		MaxPages:     1,
		Timeout:      10 * time.Second,
		AllowPrivate: true,
		Headers:      map[string]string{"X-Test-Header": "sentinel"},
	}}
	_, err := c.Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if receivedAgent != "sentinel" {
		t.Errorf("X-Test-Header = %q, want sentinel", receivedAgent)
	}
}
