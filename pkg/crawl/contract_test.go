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
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// isPagePath reports whether path matches the fixture's page pattern "/p<digits>".
// Used by TestCrawlerContract_RespectsMaxPages to distinguish crawled page URLs
// from sub-resources (favicon, about:blank, CDP targets, etc.).
func isPagePath(path string) bool {
	if !strings.HasPrefix(path, "/p") {
		return false
	}
	rest := path[2:]
	if len(rest) == 0 {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// chromeOnce guards a single Chrome availability probe shared across all
// contract test rows. Probing once avoids launching multiple Chrome processes
// for the availability check.
var (
	chromeOnce sync.Once
	chromeErr  error
)

// skipIfNoChrome skips t when a headless Chrome cannot be launched.
// It uses NewBrowserManager (browser.go:60) as the probe — the same launch
// path RodCrawler.Crawl uses — so the skip reason matches real runtime
// behavior. The result is cached in a sync.Once to avoid launching Chrome for
// every subtest row.
func skipIfNoChrome(t *testing.T) {
	t.Helper()
	chromeOnce.Do(func() {
		bm, err := NewBrowserManager(BrowserOptions{Headless: true})
		if err != nil {
			chromeErr = err
			return
		}
		bm.Close()
	})
	if chromeErr != nil {
		t.Skipf("skipping headless backend: Chrome unavailable: %v", chromeErr)
	}
}

// crawlerContractCase is one backend row in the parameterized contract table.
type crawlerContractCase struct {
	name     string
	headless bool
}

// crawlerBackends returns the two backends to exercise. This whole file is
// behind `//go:build integration` (matching the repo's Chrome-test convention),
// so default `make test` never runs it; the rod row additionally self-skips via
// skipIfNoChrome when Chrome is unavailable under the integration build.
func crawlerBackends() []crawlerContractCase {
	return []crawlerContractCase{
		{name: "http", headless: false},
		{name: "rod", headless: true},
	}
}

// runCrawlerContract runs check against both backends. makeOpts receives the
// backend's Headless value and returns the full CrawlerOptions for that row.
// The rod row skips cleanly when Chrome is unavailable.
func runCrawlerContract(
	t *testing.T,
	server *httptest.Server,
	makeOpts func(headless bool) CrawlerOptions,
	check func(t *testing.T, got []ObservedRequest, err error),
) {
	t.Helper()
	for _, bc := range crawlerBackends() {
		t.Run(bc.name, func(t *testing.T) {
			if bc.headless {
				skipIfNoChrome(t)
			}
			c := NewCrawler(makeOpts(bc.headless)) // crawler.go:94 — shared seam
			got, err := c.Crawl(context.Background(), server.URL)
			check(t, got, err)
		})
	}
}

// TestCrawlerContract_FollowsLinks asserts that both backends discover and
// follow <a href> links from an httptest server. This is the most fundamental
// crawler behavior: the seed page links to /p2 and the crawler must visit it.
func TestCrawlerContract_FollowsLinks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body><a href="/p2">page 2</a></body></html>`)
		case "/p2":
			fmt.Fprint(w, `<html><body><p>page 2</p></body></html>`)
		}
	}))
	defer srv.Close()

	runCrawlerContract(t, srv,
		func(headless bool) CrawlerOptions {
			return CrawlerOptions{
				Depth: 2, MaxPages: 10, Timeout: 30 * time.Second,
				AllowPrivate: true, Headless: headless,
			}
		},
		func(t *testing.T, got []ObservedRequest, err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("Crawl error: %v", err)
			}
			if len(got) < 2 {
				t.Errorf("got %d requests, want ≥2 (seed + /p2)", len(got))
			}
			var foundP2 bool
			for _, r := range got {
				if strings.Contains(r.URL, "/p2") {
					foundP2 = true
					break
				}
			}
			if !foundP2 {
				t.Error("/p2 was not crawled — link following broken")
			}
		},
	)
}

// TestCrawlerContract_RespectsMaxPages asserts that both backends stop actual
// crawl WORK after at most MaxPages pages. The fixture serves 50 inter-linked
// pages; with MaxPages=5 the server must receive at most maxPages+2 page-path
// requests (a small margin accounts for in-flight requests that were already
// dispatched before the cap triggers with Concurrency:1).
//
// The server-side counter is the critical assertion: counting URLs in the
// result slice only tests capping of stored results, not actual fetch work
// (both backends already cap the result slice by construction). The counter
// verifies that the crawler stops dispatching requests after the limit, not
// just stops storing them.
func TestCrawlerContract_RespectsMaxPages(t *testing.T) {
	const totalPages = 50
	const maxPages = 5
	// margin: with Concurrency=1 there is at most 1 in-flight request beyond
	// the cap trigger. Allow 2 to accommodate any final in-flight request that
	// completes after cancel() is called but before the worker loop exits.
	const fetchMargin = 2

	var serverPageFetches atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Count server-side page hits: "/" (seed) and "/p<digits>" (leaves).
		// Sub-resources (favicon, about:blank, CDP internal) are excluded so
		// the counter is comparable across both http and rod backends.
		p := r.URL.Path
		if p == "/" || isPagePath(p) {
			serverPageFetches.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		if p == "/" {
			var b strings.Builder
			for i := range totalPages {
				fmt.Fprintf(&b, `<a href="/p%d">p%d</a>`, i, i)
			}
			fmt.Fprintf(w, "<html><body>%s</body></html>", b.String())
			return
		}
		for i := range totalPages {
			if p == fmt.Sprintf("/p%d", i) {
				fmt.Fprint(w, `<html><body><p>leaf</p></body></html>`)
				return
			}
		}
	}))
	defer srv.Close()

	for _, bc := range crawlerBackends() {
		t.Run(bc.name, func(t *testing.T) {
			if bc.headless {
				skipIfNoChrome(t)
			}
			// Reset the server counter for each backend sub-test.
			serverPageFetches.Store(0)

			// Concurrency:1 bounds in-flight overshoot to at most 1 extra
			// page request beyond the cap trigger, making the margin tight.
			c := NewCrawler(CrawlerOptions{
				Depth: 5, MaxPages: maxPages, Timeout: 30 * time.Second,
				AllowPrivate: true, Headless: bc.headless, Concurrency: 1,
			})
			got, err := c.Crawl(context.Background(), srv.URL)
			if err != nil {
				t.Fatalf("Crawl error: %v", err)
			}

			// Sanity: the seed must have been crawled.
			if len(got) == 0 {
				t.Fatal("crawl returned zero results — seed was not crawled")
			}

			// Primary assertion: the SERVER received at most maxPages+fetchMargin
			// page requests. This verifies MaxPages bounds actual crawl work, not
			// just result storage.
			fetches := int(serverPageFetches.Load())
			if fetches > maxPages+fetchMargin {
				t.Errorf("server received %d page fetches, want ≤%d (maxPages=%d + margin=%d) — MaxPages does not bound crawl work",
					fetches, maxPages+fetchMargin, maxPages, fetchMargin)
			}
			// Guard: the crawler stopped far short of totalPages, confirming the
			// limit is real and not just rounding against a near-totalPages run.
			if fetches >= totalPages {
				t.Errorf("server received %d page fetches — as many as totalPages=%d; MaxPages limit had no effect",
					fetches, totalPages)
			}

			// Count distinct result page URLs for the result-slice sanity check
			// (kept as a secondary assertion alongside the server counter).
			pageURLs := make(map[string]struct{})
			for _, r := range got {
				u, err := url.Parse(r.URL)
				if err != nil {
					continue
				}
				p := u.Path
				if p == "/" || isPagePath(p) {
					pageURLs[r.URL] = struct{}{}
				}
			}
			if len(pageURLs) > maxPages {
				t.Errorf("result slice has %d distinct page URLs, want ≤%d — MaxPages not respected in results",
					len(pageURLs), maxPages)
			}
		})
	}
}

// TestCrawlerContract_SendsCustomHeaders asserts that both backends inject
// caller-supplied headers into outbound requests. The fixture records the
// header value received from the crawler.
func TestCrawlerContract_SendsCustomHeaders(t *testing.T) {
	const headerName = "X-Contract-Test"
	const headerVal = "hello-from-contract"

	// sawHeader: header value received on ANY request (seed or followed).
	// sawHeaderOnP2: header value received specifically on the followed /p2 request.
	// This ensures the header is injected on followed requests, not only the seed.
	var sawHeader, sawHeaderOnP2 string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if v := r.Header.Get(headerName); v != "" {
			sawHeader = v
			if r.URL.Path == "/p2" {
				sawHeaderOnP2 = v
			}
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			// Seed links to /p2 so the crawler follows at least one link.
			fmt.Fprint(w, `<html><body><a href="/p2">page 2</a></body></html>`)
		default:
			fmt.Fprint(w, `<html><body>ok</body></html>`)
		}
	}))
	defer srv.Close()

	runCrawlerContract(t, srv,
		func(headless bool) CrawlerOptions {
			return CrawlerOptions{
				Depth: 2, MaxPages: 5, Timeout: 30 * time.Second,
				AllowPrivate: true, Headless: headless,
				Headers: map[string]string{headerName: headerVal},
			}
		},
		func(t *testing.T, got []ObservedRequest, err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("Crawl error: %v", err)
			}
			mu.Lock()
			v := sawHeader
			v2 := sawHeaderOnP2
			mu.Unlock()
			if v != headerVal {
				t.Errorf("custom header %s not received by server: got %q, want %q",
					headerName, v, headerVal)
			}
			// Assert the header was also received on the followed /p2 request
			// (not only on the seed), verifying header injection on non-seed pages.
			if v2 != headerVal {
				t.Errorf("custom header %s not received on followed /p2 request: got %q, want %q",
					headerName, v2, headerVal)
			}
		},
	)
}

// TestCrawlerContract_ScopeConfinement asserts the NEGATIVE: neither backend
// follows cross-origin links. The fixture serves a page linking to an
// external origin; neither crawler result should contain the off-origin URL.
//
// This tests cross-origin LINK confinement enforced at the frontier
// (scope.go scopeChecker via frontier.Push) — both backends share this guard.
// It does NOT test redirect-Location SSRF (HTTP-only; see http_crawler_test.go).
func TestCrawlerContract_ScopeConfinement(t *testing.T) {
	// A second server plays the role of a different origin.
	offOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><p>off-origin</p></body></html>`)
	}))
	defer offOrigin.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Page links to both a same-origin page and the off-origin server.
		fmt.Fprintf(w,
			`<html><body><a href="/local">local</a><a href="%s/off">off</a></body></html>`,
			offOrigin.URL,
		)
	}))
	defer srv.Close()

	runCrawlerContract(t, srv,
		func(headless bool) CrawlerOptions {
			return CrawlerOptions{
				Depth: 2, MaxPages: 20, Timeout: 30 * time.Second,
				Scope: "same-origin", AllowPrivate: true, Headless: headless,
			}
		},
		func(t *testing.T, got []ObservedRequest, err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("Crawl error: %v", err)
			}
			// NEGATIVE assertion: no result URL should be on the off-origin server.
			for _, r := range got {
				if strings.Contains(r.URL, offOrigin.URL) {
					t.Errorf("crawler followed cross-origin link — scope confinement broken: %s", r.URL)
				}
			}
		},
	)
}

// TestCrawlerContract_RelativeLinksResolvedAgainstFinalURL verifies that
// relative links are resolved against the post-redirect base URL, not the
// seed URL. Both backends must fetch /app/next (resolved from /app/ + "next"),
// not /next (resolved from the seed /start + "next").
func TestCrawlerContract_RelativeLinksResolvedAgainstFinalURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/app/", http.StatusFound)
		case "/app/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><a href="next">next</a></body></html>`)
		case "/app/next":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><p>correct</p></body></html>`)
		case "/next":
			// This path is wrong — relative link resolved against seed, not final URL.
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><p>wrong</p></body></html>`)
		}
	}))
	defer srv.Close()

	// Use a custom server URL with /start suffix so the redirect happens.
	// runCrawlerContract is not used here because it always seeds with server.URL;
	// this test requires a non-root seed URL (/start) to exercise redirect resolution.
	startURL := srv.URL + "/start"
	for _, bc := range crawlerBackends() {
		t.Run(bc.name, func(t *testing.T) {
			if bc.headless {
				skipIfNoChrome(t)
			}
			c := NewCrawler(CrawlerOptions{
				Depth: 3, MaxPages: 20, Timeout: 30 * time.Second,
				AllowPrivate: true, Headless: bc.headless,
			})
			got, err := c.Crawl(context.Background(), startURL)
			if err != nil {
				t.Fatalf("Crawl error: %v", err)
			}
			var foundAppNext, foundBadNext bool
			for _, r := range got {
				if strings.Contains(r.URL, "/app/next") {
					foundAppNext = true
				}
				if strings.HasSuffix(r.URL, "/next") && !strings.Contains(r.URL, "/app/next") {
					foundBadNext = true
				}
			}
			if !foundAppNext {
				t.Error("expected /app/next to be crawled (relative link resolved against final URL)")
			}
			if foundBadNext {
				t.Error("/next was crawled — relative link resolved against seed URL, not post-redirect URL")
			}
		})
	}
}

// TestCrawlerContract_DepthLimit verifies that both backends respect the Depth
// limit and do not crawl pages beyond it. The fixture forms a chain of depth-4
// pages; with Depth=2 only the first two levels should be visited.
func TestCrawlerContract_DepthLimit(t *testing.T) {
	// Chain: / → /d1 → /d2 → /d3 → /d4
	// With Depth:2, /d3 and /d4 must not be visited.
	const chainLen = 4

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		for i := range chainLen {
			if r.URL.Path == fmt.Sprintf("/d%d", i) || (i == 0 && r.URL.Path == "/") {
				next := i + 1
				if next <= chainLen {
					fmt.Fprintf(w, `<html><body><a href="/d%d">next</a></body></html>`, next)
				} else {
					fmt.Fprint(w, `<html><body><p>end</p></body></html>`)
				}
				return
			}
		}
		fmt.Fprint(w, `<html><body><p>leaf</p></body></html>`)
	}))
	defer srv.Close()

	runCrawlerContract(t, srv,
		func(headless bool) CrawlerOptions {
			return CrawlerOptions{
				Depth: 2, MaxPages: 100, Timeout: 30 * time.Second,
				AllowPrivate: true, Headless: headless,
			}
		},
		func(t *testing.T, got []ObservedRequest, err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("Crawl error: %v", err)
			}
			// Depth semantics: seed "/" is depth 0; each hop increments by 1.
			// With Depth=2:
			//   depth 0: /       ← must be visited (seed)
			//   depth 1: /d1     ← must be visited (one hop from seed)
			//   depth 2: /d2     ← must be visited (exactly at limit)
			//   depth 3: /d3     ← must NOT be visited (one beyond limit)
			//   depth 4: /d4     ← must NOT be visited (two beyond limit)
			var foundD2, foundD3, foundD4 bool
			for _, r := range got {
				switch {
				case strings.Contains(r.URL, "/d2"):
					foundD2 = true
				case strings.Contains(r.URL, "/d3"):
					foundD3 = true
				case strings.Contains(r.URL, "/d4"):
					foundD4 = true
				}
			}
			// /d2 is exactly at the depth limit and must be reachable.
			if !foundD2 {
				t.Error("/d2 (depth=2, at limit) was not crawled — depth limit too aggressive")
			}
			// /d3 and /d4 are beyond the depth limit and must not appear.
			if foundD3 {
				t.Error("depth limit breached — /d3 (depth=3, beyond limit=2) was crawled")
			}
			if foundD4 {
				t.Error("depth limit breached — /d4 (depth=4, beyond limit=2) was crawled")
			}
		},
	)
}
