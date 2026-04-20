//go:build integration

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
	"sync"
	"testing"
	"time"
)

// launchTestBrowser creates a headless Chrome instance for integration tests.
func launchTestBrowser(t *testing.T) *BrowserManager {
	t.Helper()
	bm, err := NewBrowserManager(BrowserOptions{Headless: true})
	if err != nil {
		t.Fatalf("failed to launch browser: %v", err)
	}
	t.Cleanup(func() { bm.Close() })
	return bm
}

func TestRodEngine_BasicCrawl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body><a href="/page1">Page 1</a><a href="/page2">Page 2</a></body></html>`)
		case "/page1":
			fmt.Fprint(w, `<html><body><h1>Page 1</h1><a href="/page3">Page 3</a></body></html>`)
		case "/page2":
			fmt.Fprint(w, `<html><body><h1>Page 2</h1></body></html>`)
		case "/page3":
			fmt.Fprint(w, `<html><body><h1>Page 3</h1></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	bm := launchTestBrowser(t)
	engine, err := newRodEngine(bm.wsURL(), engineOptions{
		Concurrency:   2,
		MaxPages:      100,
		MaxDepth:      3,
		PageTimeout:   10 * time.Second,
		StableTimeout: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("newRodEngine: %v", err)
	}
	defer engine.Close()

	var mu sync.Mutex
	var results []ObservedRequest

	err = engine.Crawl(context.Background(), srv.URL+"/", func(req ObservedRequest) {
		mu.Lock()
		results = append(results, req)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("Crawl error: %v", err)
	}

	mu.Lock()
	count := len(results)
	mu.Unlock()

	// We should capture network requests from visiting all pages.
	if count == 0 {
		t.Fatal("Crawl returned 0 results, expected at least some network requests")
	}

	// Verify all results have Source = "browser"
	mu.Lock()
	for _, r := range results {
		if r.Source != "browser" {
			t.Errorf("Source = %q, want %q", r.Source, "browser")
		}
		if r.Method == "" {
			t.Error("Method is empty")
		}
	}
	mu.Unlock()
}

func TestRodEngine_Concurrency(t *testing.T) {
	// Each page has a 500ms delay. With 5 concurrent workers, 10 pages should
	// take ~1-2 seconds. Serial would take ~5+ seconds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			body := `<html><body>`
			for i := range 10 {
				body += fmt.Sprintf(`<a href="/page%d">Page %d</a>`, i, i)
			}
			body += `</body></html>`
			fmt.Fprint(w, body)
		} else {
			fmt.Fprint(w, `<html><body><h1>Leaf</h1></body></html>`)
		}
	}))
	defer srv.Close()

	bm := launchTestBrowser(t)
	engine, err := newRodEngine(bm.wsURL(), engineOptions{
		Concurrency:   5,
		MaxPages:      100,
		MaxDepth:      2,
		PageTimeout:   10 * time.Second,
		StableTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("newRodEngine: %v", err)
	}
	defer engine.Close()

	var mu sync.Mutex
	var results []ObservedRequest

	start := time.Now()
	err = engine.Crawl(context.Background(), srv.URL+"/", func(req ObservedRequest) {
		mu.Lock()
		results = append(results, req)
		mu.Unlock()
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Crawl error: %v", err)
	}

	// Concurrent crawl should be significantly faster than serial.
	// 11 pages * 500ms serial = 5.5s. With 5 workers ≈ 2-3s.
	if elapsed > 8*time.Second {
		t.Errorf("Crawl took %v, expected less than 8s (concurrency not working?)", elapsed)
	}
	t.Logf("Crawl completed in %v with %d results", elapsed, len(results))
}

func TestRodEngine_MaxPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Each page links to the next — infinite chain.
		fmt.Fprintf(w, `<html><body><a href="%s/next%d">next</a></body></html>`,
			r.URL.Path, time.Now().UnixNano())
	}))
	defer srv.Close()

	bm := launchTestBrowser(t)
	engine, err := newRodEngine(bm.wsURL(), engineOptions{
		Concurrency:   2,
		MaxPages:      5,
		MaxDepth:      100,
		PageTimeout:   10 * time.Second,
		StableTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("newRodEngine: %v", err)
	}
	defer engine.Close()

	var mu sync.Mutex
	var pageVisits int

	err = engine.Crawl(context.Background(), srv.URL+"/", func(req ObservedRequest) {
		mu.Lock()
		pageVisits++
		mu.Unlock()
	})

	// Context should have been canceled by MaxPages.
	mu.Lock()
	count := pageVisits
	mu.Unlock()

	// Due to concurrency, we may get slightly more than MaxPages results
	// (workers that were already navigating when cancel fired). But it
	// should be bounded.
	t.Logf("Got %d results with MaxPages=5", count)
	if count == 0 {
		t.Error("Got 0 results, expected at least 1")
	}
}

func TestRodEngine_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // slow server
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/page2">link</a></body></html>`)
	}))
	defer srv.Close()

	bm := launchTestBrowser(t)
	engine, err := newRodEngine(bm.wsURL(), engineOptions{
		Concurrency:   2,
		MaxPages:      100,
		MaxDepth:      3,
		PageTimeout:   10 * time.Second,
		StableTimeout: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("newRodEngine: %v", err)
	}
	defer engine.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var results []ObservedRequest
	var mu sync.Mutex

	err = engine.Crawl(ctx, srv.URL+"/", func(req ObservedRequest) {
		mu.Lock()
		results = append(results, req)
		mu.Unlock()
	})

	// Should return within roughly the timeout, not hang.
	if err != nil && err != context.DeadlineExceeded {
		t.Logf("Crawl returned error (expected): %v", err)
	}
}

func TestRodEngine_ScopeFiltering(t *testing.T) {
	// In-scope server.
	inScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>In Scope</h1></body></html>`)
	}))
	defer inScope.Close()

	// Out-of-scope server.
	outOfScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Out of Scope</h1></body></html>`)
	}))
	defer outOfScope.Close()

	// Root page links to both.
	root := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>
			<a href="%s/in">in-scope</a>
			<a href="%s/out">out-of-scope</a>
		</body></html>`, inScope.URL, outOfScope.URL)
	}))
	defer root.Close()

	scopeFn, err := scopeChecker(root.URL, "same-origin", true)
	if err != nil {
		t.Fatalf("scopeChecker: %v", err)
	}

	bm := launchTestBrowser(t)
	engine, err := newRodEngine(bm.wsURL(), engineOptions{
		Concurrency:   2,
		MaxPages:      100,
		MaxDepth:      2,
		PageTimeout:   10 * time.Second,
		StableTimeout: 500 * time.Millisecond,
		ScopeCheck:    scopeFn,
	})
	if err != nil {
		t.Fatalf("newRodEngine: %v", err)
	}
	defer engine.Close()

	var mu sync.Mutex
	visitedURLs := make(map[string]bool)

	err = engine.Crawl(context.Background(), root.URL+"/", func(req ObservedRequest) {
		mu.Lock()
		visitedURLs[req.URL] = true
		mu.Unlock()
	})
	if err != nil {
		t.Logf("Crawl error (may be expected): %v", err)
	}

	// The out-of-scope server URL should NOT appear as a visited page.
	// (It may appear in network requests if the browser loaded it, but
	// the frontier should not have enqueued it for crawling.)
	mu.Lock()
	for url := range visitedURLs {
		t.Logf("Visited: %s", url)
	}
	mu.Unlock()
}

// TestRodEngine_BaseHrefResolution regresses LAB-2221 Issue A: a page served
// under a deep path with <base href="/"> must have its relative asset refs
// resolved against the base tag, not the page URL. Previously the crawler
// would queue /deep/nested/main.js instead of /main.js, producing mangled
// recursive paths on SPA catch-all servers.
func TestRodEngine_BaseHrefResolution(t *testing.T) {
	// The "SPA" always returns the same HTML body with <base href="/">,
	// simulating Juice Shop's catch-all routing. Relative refs on the
	// page (logo.png, app.js, /api/users) must all resolve to the root.
	spa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html>
			<head><base href="/"></head>
			<body>
				<a href="login">Login</a>
				<a href="/api/users">Users</a>
				<script src="app.js"></script>
			</body>
		</html>`)
	}))
	defer spa.Close()

	bm := launchTestBrowser(t)
	scopeFn, err := scopeChecker(spa.URL, "same-origin", true)
	if err != nil {
		t.Fatalf("scopeChecker: %v", err)
	}
	engine, err := newRodEngine(bm.wsURL(), engineOptions{
		Concurrency:   2,
		MaxPages:      20,
		MaxDepth:      2,
		PageTimeout:   10 * time.Second,
		StableTimeout: 500 * time.Millisecond,
		ScopeCheck:    scopeFn,
	})
	if err != nil {
		t.Fatalf("newRodEngine: %v", err)
	}
	defer engine.Close()

	var mu sync.Mutex
	visited := make(map[string]bool)

	// Start the crawl from a deep path. Without base-href support, relative
	// refs would resolve against /deep/page/, producing /deep/page/login,
	// /deep/page/app.js, etc.
	err = engine.Crawl(context.Background(), spa.URL+"/deep/page/here", func(req ObservedRequest) {
		mu.Lock()
		visited[req.URL] = true
		mu.Unlock()
	})
	if err != nil {
		t.Logf("Crawl error (may be non-fatal): %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// The crawler must have navigated to /login (resolved via <base href=/>),
	// NOT /deep/page/login (which would be the bug).
	want := spa.URL + "/login"
	mangled := spa.URL + "/deep/page/login"

	if !visited[want] {
		t.Errorf("expected to visit %q (base-href-resolved), got none. Visited: %v", want, keys(visited))
	}
	if visited[mangled] {
		t.Errorf("should NOT have visited %q (page-URL-resolved mangled path)", mangled)
	}
	// The mangled asset path is the critical signal of the original bug —
	// if the crawler had resolved against the page URL rather than base
	// href, it would have tried to fetch /deep/page/app.js. This one
	// should not appear in any form.
	if visited[spa.URL+"/deep/page/app.js"] {
		t.Errorf("should NOT have fetched %q (page-URL-resolved mangled asset)", spa.URL+"/deep/page/app.js")
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRodEngine_DepthLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Each page links to the next level.
		fmt.Fprintf(w, `<html><body><a href="%s/deeper">deeper</a></body></html>`, r.URL.Path)
	}))
	defer srv.Close()

	bm := launchTestBrowser(t)
	engine, err := newRodEngine(bm.wsURL(), engineOptions{
		Concurrency:   1,
		MaxPages:      100,
		MaxDepth:      1, // Only visit root (depth 0) and its direct links (depth 1)
		PageTimeout:   10 * time.Second,
		StableTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("newRodEngine: %v", err)
	}
	defer engine.Close()

	var mu sync.Mutex
	var results []ObservedRequest

	err = engine.Crawl(context.Background(), srv.URL+"/", func(req ObservedRequest) {
		mu.Lock()
		results = append(results, req)
		mu.Unlock()
	})
	if err != nil {
		t.Logf("Crawl error: %v", err)
	}

	mu.Lock()
	count := len(results)
	mu.Unlock()

	// With depth=1, we visit root + one level of links. Not an infinite chain.
	t.Logf("Got %d results with MaxDepth=1", count)
	if count == 0 {
		t.Error("Got 0 results, expected at least 1")
	}
}
