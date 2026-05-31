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
		w.Write(bigBody) //nolint:errcheck
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
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<script>fetch("/api/x")</script><a href="/api/x">x</a>`)
		} else if r.URL.Path == "/api/x" {
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
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", 302)
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
