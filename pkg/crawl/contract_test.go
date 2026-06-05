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
	"strings"
	"sync"
	"testing"
	"time"
)

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
		bc := bc // capture range variable
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

// TestCrawlerContract_RespectsMaxPages asserts that both backends stop after
// crawling at most MaxPages pages. The fixture serves 50 inter-linked pages;
// limiting to 5 must cap results well below 50.
func TestCrawlerContract_RespectsMaxPages(t *testing.T) {
	const totalPages = 50
	const maxPages = 5

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			var b strings.Builder
			for i := range totalPages {
				fmt.Fprintf(&b, `<a href="/p%d">p%d</a>`, i, i)
			}
			fmt.Fprintf(w, "<html><body>%s</body></html>", b.String())
			return
		}
		for i := range totalPages {
			if r.URL.Path == fmt.Sprintf("/p%d", i) {
				fmt.Fprint(w, `<html><body><p>leaf</p></body></html>`)
				return
			}
		}
	}))
	defer srv.Close()

	runCrawlerContract(t, srv,
		func(headless bool) CrawlerOptions {
			return CrawlerOptions{
				Depth: 5, MaxPages: maxPages, Timeout: 30 * time.Second,
				AllowPrivate: true, Headless: headless,
			}
		},
		func(t *testing.T, got []ObservedRequest, err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("Crawl error: %v", err)
			}
			// MaxPages bounds the pages crawled, not necessarily each request
			// (rod may capture sub-resources). The key invariant: far fewer than
			// totalPages(50) distinct page URLs observed.
			uniqueURLs := make(map[string]struct{})
			for _, r := range got {
				uniqueURLs[r.URL] = struct{}{}
			}
			if len(uniqueURLs) > totalPages/2 {
				t.Errorf("got %d unique URLs, want ≤%d — MaxPages not respected",
					len(uniqueURLs), totalPages/2)
			}
		},
	)
}

// TestCrawlerContract_SendsCustomHeaders asserts that both backends inject
// caller-supplied headers into outbound requests. The fixture records the
// header value received from the crawler.
func TestCrawlerContract_SendsCustomHeaders(t *testing.T) {
	const headerName = "X-Contract-Test"
	const headerVal = "hello-from-contract"

	var sawHeader string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if v := r.Header.Get(headerName); v != "" {
			sawHeader = v
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>ok</body></html>`)
	}))
	defer srv.Close()

	runCrawlerContract(t, srv,
		func(headless bool) CrawlerOptions {
			return CrawlerOptions{
				Depth: 1, MaxPages: 5, Timeout: 30 * time.Second,
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
			mu.Unlock()
			if v != headerVal {
				t.Errorf("custom header %s not received by server: got %q, want %q",
					headerName, v, headerVal)
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
	startURL := srv.URL + "/start"
	for _, bc := range crawlerBackends() {
		bc := bc
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
			// /d3 and /d4 are at depth >2 and must not appear.
			for _, r := range got {
				if strings.Contains(r.URL, "/d3") || strings.Contains(r.URL, "/d4") {
					t.Errorf("depth limit breached — URL beyond depth=2 crawled: %s", r.URL)
				}
			}
		},
	)
}
