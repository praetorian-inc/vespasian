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
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMaxHTTPBodySize verifies the MaxHTTPBodySize constant value.
func TestMaxHTTPBodySize(t *testing.T) {
	if MaxHTTPBodySize != 10*1024*1024 {
		t.Errorf("MaxHTTPBodySize = %d, want 10 MiB", MaxHTTPBodySize)
	}
}

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

// TestValidateProxyAddr tests the proxy address validation.
func TestValidateProxyAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
		errMsg  string
	}{
		{"valid http", "http://127.0.0.1:8080", false, ""},
		{"valid https", "https://proxy.example.com:8443", false, ""},
		{"valid socks5", "socks5://127.0.0.1:1080", false, ""},
		{"valid http no port", "http://proxy.local", false, ""},
		{"missing scheme", "127.0.0.1:8080", true, "invalid proxy address"},
		{"ftp scheme", "ftp://proxy:21", true, "scheme must be"},
		{"empty host", "http://", true, "missing host"},
		{"embedded credentials", "http://user:pass@127.0.0.1:8080", true, "embedded credentials"},
		{"embedded user only", "http://user@127.0.0.1:8080", true, "embedded credentials"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProxyAddr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateProxyAddr(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateProxyAddr(%q) error = %q, want containing %q", tt.addr, err.Error(), tt.errMsg)
				}
			}
		})
	}

	// Verify credentials are never echoed in error messages, even when
	// other validation (e.g., scheme) would also fail.
	credentialLeakCases := []struct {
		name string
		addr string
	}{
		{"http with creds", "http://admin:s3cret@proxy:8080"},
		{"wrong scheme with creds", "ftp://admin:s3cret@proxy:21"},
		{"user only", "http://admin@proxy:8080"},
	}
	for _, tt := range credentialLeakCases {
		t.Run("redacted/"+tt.name, func(t *testing.T) {
			err := validateProxyAddr(tt.addr)
			if err == nil {
				t.Fatal("expected error for embedded credentials")
			}
			msg := err.Error()
			if strings.Contains(msg, "admin") || strings.Contains(msg, "s3cret") {
				t.Errorf("error message leaks credentials: %s", msg)
			}
			if !strings.Contains(msg, "xxxxx") {
				t.Errorf("error message should contain redacted placeholder 'xxxxx': %s", msg)
			}
		})
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
