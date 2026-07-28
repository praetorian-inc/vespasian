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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestValidateCrawlInputs tests the shared validateCrawlInputs helper.
func TestValidateCrawlInputs(t *testing.T) {
	if _, err := validateCrawlInputs(CrawlerOptions{Depth: -1}, "https://e.com"); err == nil ||
		!strings.Contains(err.Error(), "depth must be non-negative") {
		t.Errorf("negative depth: %v", err)
	}
	if _, err := validateCrawlInputs(CrawlerOptions{}, ""); err == nil ||
		!strings.Contains(err.Error(), "invalid target URL") {
		t.Errorf("empty url: %v", err)
	}
	if mp, err := validateCrawlInputs(CrawlerOptions{MaxPages: 0}, "https://e.com"); err != nil || mp != DefaultMaxPages {
		t.Errorf("default maxpages: mp=%d err=%v", mp, err)
	}
}

// TestNewCrawler_ReturnsInterface verifies NewCrawler returns the correct concrete type.
func TestNewCrawler_ReturnsInterface(t *testing.T) {
	h := NewCrawler(CrawlerOptions{Headless: true})
	if _, ok := h.(*RodCrawler); !ok {
		t.Fatalf("Headless:true → got %T, want *RodCrawler", h)
	}
	s := NewCrawler(CrawlerOptions{Headless: false})
	if _, ok := s.(*HTTPCrawler); !ok {
		t.Fatalf("Headless:false → got %T, want *HTTPCrawler", s)
	}
}

// TestNewCrawler tests the constructor
func TestNewCrawler(t *testing.T) {
	opts := CrawlerOptions{Depth: 5, MaxPages: 100, Scope: "same-domain", Headless: true,
		Proxy: "http://127.0.0.1:8080", Headers: map[string]string{"User-Agent": "test"}}
	c := NewCrawler(opts)
	rc, ok := c.(*RodCrawler)
	if !ok {
		t.Fatalf("Headless:true → %T, want *RodCrawler", c)
	}
	if rc.opts.Depth != 5 || rc.opts.MaxPages != 100 || rc.opts.Scope != "same-domain" ||
		!rc.opts.Headless || rc.opts.Proxy != "http://127.0.0.1:8080" ||
		rc.opts.Headers["User-Agent"] != "test" {
		t.Errorf("opts not stored: %+v", rc.opts)
	}
}

// TestCrawl_NegativeDepthReturnsError tests that negative depth is rejected
func TestCrawl_NegativeDepthReturnsError(t *testing.T) {
	crawler := NewCrawler(CrawlerOptions{
		Depth: -1,
	})
	_, err := crawler.Crawl(context.Background(), "https://example.com")
	if err == nil {
		t.Fatal("expected error for negative depth, got nil")
	}
	if !strings.Contains(err.Error(), "depth must be non-negative") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestDefaultMaxPages verifies the DefaultMaxPages constant value
func TestDefaultMaxPages(t *testing.T) {
	if DefaultMaxPages != 1000 {
		t.Errorf("DefaultMaxPages = %d, want 1000", DefaultMaxPages)
	}
}

// TestCrawl_EmptyURLReturnsError tests that empty URL is rejected
func TestCrawl_EmptyURLReturnsError(t *testing.T) {
	crawler := NewCrawler(CrawlerOptions{
		Depth: 3,
	})
	_, err := crawler.Crawl(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty URL, got nil")
	}
	if !strings.Contains(err.Error(), "invalid target URL") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestPageTimeout verifies the PageTimeout constant value
func TestPageTimeout(t *testing.T) {
	if PageTimeout != 30 {
		t.Errorf("PageTimeout = %d, want 30", PageTimeout)
	}
}

// TestCrawl_InvalidSchemeReturnsError tests that URLs without http/https scheme
// are rejected, including non-HTTP schemes that could be SSRF vectors.
func TestCrawl_InvalidSchemeReturnsError(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"schemeless", "not-a-url"},
		{"file scheme", "file:///etc/passwd"},
		{"ftp scheme", "ftp://example.com"},
		{"empty host", "http:///path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crawler := NewCrawler(CrawlerOptions{Depth: 3})
			_, err := crawler.Crawl(context.Background(), tt.url)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tt.url)
			}
			if !strings.Contains(err.Error(), "invalid target URL") {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	}
}

// TestCrawl_SignalPath_ReturnsContextCanceled verifies that when the parent
// context is canceled (simulating SIGINT/SIGTERM), Crawl() returns
// context.Canceled and writes an interrupt message to Stderr.
func TestCrawl_SignalPath_ReturnsContextCanceled(t *testing.T) {
	// Slow server to ensure the crawl is still running when we cancel.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="/page2">link</a></body></html>`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer

	crawler := NewCrawler(CrawlerOptions{
		Depth:        1,
		MaxPages:     100,
		Timeout:      30 * time.Second,
		Headless:     false,
		Stderr:       &stderr,
		AllowPrivate: true,
	})

	// Cancel context immediately to trigger signal path.
	cancel()

	_, err := crawler.Crawl(ctx, srv.URL)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Crawl() error = %v, want context.Canceled", err)
	}
	if !strings.Contains(stderr.String(), "interrupt received") {
		t.Errorf("stderr = %q, want message containing 'interrupt received'", stderr.String())
	}
}

// TestCrawl_SignalPath_NilStderr verifies that Crawl() does not panic
// when Stderr is nil on the signal path.
func TestCrawl_SignalPath_NilStderr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>hello</body></html>`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	crawler := NewCrawler(CrawlerOptions{
		Depth:        1,
		MaxPages:     100,
		Timeout:      30 * time.Second,
		Headless:     false,
		Stderr:       nil, // explicitly nil
		AllowPrivate: true,
	})

	_, err := crawler.Crawl(ctx, srv.URL)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Crawl() error = %v, want context.Canceled", err)
	}
}

// TestCrawl_MaxPagesPath_ReturnsNoError verifies that when MaxPages is reached,
// Crawl() returns results without an error.
func TestCrawl_MaxPagesPath_ReturnsNoError(t *testing.T) {
	// Server that returns pages with links, generating enough results to hit MaxPages.
	var requestCount int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		n := requestCount
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html")
		// Each page links to the next, up to a high number.
		fmt.Fprintf(w, `<html><body><a href="/page%d">next</a></body></html>`, n+1)
	}))
	defer srv.Close()

	crawler := NewCrawler(CrawlerOptions{
		Depth:        10,
		MaxPages:     2,
		Timeout:      30 * time.Second,
		Headless:     false,
		AllowPrivate: true,
	})

	results, err := crawler.Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Errorf("Crawl() unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Error("Crawl() returned 0 results, want at least 1")
	}
	if len(results) > 2 {
		t.Errorf("Crawl() returned %d results, want at most 2 (MaxPages)", len(results))
	}
}

// TestCrawl_ResumeSkipsCoveredPages drives the Phase 4 resume seam end to end
// through the exported CrawlerOptions API (LAB-4678): a budget-truncated crawl
// emits a checkpoint via OnCheckpoint, and feeding it back as ResumeFrom makes
// the next run skip the pages already covered instead of re-crawling them.
//
// This also covers the seed-already-covered path: on resume the seed is in the
// restored seen-set, so Push rejects it and the crawl must proceed from the
// restored pending queue rather than failing "seed URL rejected".
func TestCrawl_ResumeSkipsCoveredPages(t *testing.T) {
	var mu sync.Mutex
	served := map[string]int{}
	var nextID int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served[r.URL.Path]++
		// Child paths come from a counter rather than the request path: echoing
		// r.URL.Path back into the HTML is a reflection the linter flags, and the
		// test only needs distinct pages, not path structure.
		a, b := nextID+1, nextID+2
		nextID += 2
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		// Every page links to two more, so the frontier always has surplus pending
		// entries when a small page budget truncates the run.
		fmt.Fprintf(w, `<html><body><a href="/p%d">a</a><a href="/p%d">b</a></body></html>`, a, b)
	}))
	defer srv.Close()

	var cp *Checkpoint
	base := CrawlerOptions{
		Depth:        5,
		MaxPages:     3,
		Timeout:      30 * time.Second,
		Headless:     false,
		AllowPrivate: true,
		OnCheckpoint: func(c *Checkpoint) { cp = c },
	}

	first, err := NewCrawler(base).Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("first crawl: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("first crawl captured nothing")
	}
	if cp == nil {
		t.Fatal("OnCheckpoint was never invoked")
	}
	if len(cp.Pending) == 0 {
		t.Fatal("checkpoint carried no pending pages, so resume cannot continue")
	}
	if cp.ConfigFingerprint != ComputeConfigFingerprint(srv.URL, base.Scope, base.Depth, false, base.AllowPrivate) {
		t.Error("checkpoint fingerprint does not match the crawl config")
	}

	// "Covered" means recorded in the results, not merely fetched: a page whose
	// fetch completed after the budget filled has its result discarded, so it was
	// NOT covered and the resumed run is right to fetch it again.
	covered := map[string]int{}
	for _, r := range first {
		u, err := url.Parse(r.URL)
		if err != nil {
			t.Fatalf("unparseable result URL %q: %v", r.URL, err)
		}
		mu.Lock()
		covered[u.Path] = served[u.Path]
		mu.Unlock()
	}
	if len(covered) == 0 {
		t.Fatal("no covered pages recorded in the first crawl")
	}

	// Resume with the same config. Pages covered by the first run must not be
	// refetched, and the run must not fail on the already-seen seed.
	resumeOpts := base
	resumeOpts.ResumeFrom = cp
	resumeOpts.OnCheckpoint = nil
	if _, err := NewCrawler(resumeOpts).Crawl(context.Background(), srv.URL); err != nil {
		t.Fatalf("resumed crawl: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for p, n := range covered {
		if served[p] > n {
			t.Errorf("resumed crawl refetched already-covered page %s (%d -> %d)", p, n, served[p])
		}
	}
}

// TestCrawl_ResumeRejectsForeignCheckpoint verifies a checkpoint from a
// different config is ignored rather than honored: the crawl proceeds fresh and
// re-covers the seed instead of skipping it as already-seen.
func TestCrawl_ResumeRejectsForeignCheckpoint(t *testing.T) {
	var mu sync.Mutex
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>ok</body></html>`)
	}))
	defer srv.Close()

	// A checkpoint whose fingerprint belongs to another target, but which claims
	// this target's seed is already covered. Honoring it would crawl nothing.
	foreign := &Checkpoint{
		Version:           checkpointVersion,
		ConfigFingerprint: ComputeConfigFingerprint("https://elsewhere.example", "", 5, false, false),
		CreatedAtUnix:     time.Now().Unix(),
		Seen:              []string{frontierKey(srv.URL + "/")},
	}

	var stderr bytes.Buffer
	results, err := NewCrawler(CrawlerOptions{
		Depth:        5,
		MaxPages:     3,
		Timeout:      30 * time.Second,
		Headless:     false,
		AllowPrivate: true,
		ResumeFrom:   foreign,
		Stderr:       &stderr,
	}).Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("crawl with foreign checkpoint: %v", err)
	}
	if len(results) == 0 {
		t.Error("foreign checkpoint was honored: crawl captured nothing")
	}
	mu.Lock()
	defer mu.Unlock()
	if hits == 0 {
		t.Error("seed was never fetched, so the foreign seen-set was applied")
	}
	if !strings.Contains(stderr.String(), "ignoring checkpoint") {
		t.Errorf("mismatch not reported to the operator: %q", stderr.String())
	}
}

// TestCrawl_MaxRequests_HTTPBackend verifies the request budget bounds the
// net/http backend (LAB-4678 Phase 3). That backend records one request per
// page, so MaxRequests caps the captured-request count just as MaxPages would.
func TestCrawl_MaxRequests_HTTPBackend(t *testing.T) {
	var requestCount int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		n := requestCount
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="/page%d">next</a></body></html>`, n+1)
	}))
	defer srv.Close()

	crawler := NewCrawler(CrawlerOptions{
		Depth:        10,
		MaxPages:     1000, // high, so MaxRequests is the binding bound
		MaxRequests:  3,
		Timeout:      30 * time.Second,
		Headless:     false,
		AllowPrivate: true,
	})

	results, err := crawler.Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Errorf("Crawl() unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Error("Crawl() returned 0 results, want at least 1")
	}
	if len(results) > 3 {
		t.Errorf("Crawl() returned %d results, want at most 3 (MaxRequests)", len(results))
	}
}
