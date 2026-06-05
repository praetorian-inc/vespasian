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
	"testing"
	"time"
)

// TestRodCrawler_CapturesSPAFetch regresses LAB-1535: the rod (headless)
// backend must capture a fetch/XHR POST issued by inline JavaScript at page
// load. The HTTPCrawler cannot execute JavaScript and is expected to MISS it
// (documented capability gap).
//
// The test serves a minimal SPA from an httptest server — a static HTML page
// with an inline <script> that calls fetch("/graphql", {method:"POST",...}) on
// load, mirroring the pattern at test/graphql-server/server.js:213-237 but
// with zero external dependencies.
//
// Closing assertion: hasGraphQLPost(got)==true for the rod backend closes
// LAB-1535. The negative assertion for the HTTP backend documents the
// intentional capability gap and fails loudly if the gap assumption ever
// changes.
//
// Chrome must be available; test uses skipIfNoChrome (D1 gate helper) so it
// skips cleanly when run in Chrome-free CI environments.
func TestRodCrawler_CapturesSPAFetch(t *testing.T) {
	skipIfNoChrome(t)

	const spaHTML = `<!DOCTYPE html>
<html><head></head><body>
<div id="out"></div>
<script>
fetch("/graphql",{
  method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({query:"{ users { id } }"})
})
.then(function(r){return r.json();})
.then(function(d){document.getElementById("out").textContent="done";});
</script>
</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"data":{"users":[{"id":"1"}]}}`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, spaHTML)
	}))
	defer srv.Close()

	// Rod backend: MUST capture the /graphql POST (LAB-1535).
	rodCrawler := NewCrawler(CrawlerOptions{
		Depth:        1,
		MaxPages:     10,
		Timeout:      30 * time.Second,
		Scope:        "same-origin",
		Headless:     true,
		AllowPrivate: true,
	})
	rodGot, err := rodCrawler.Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("rod crawl: %v", err)
	}
	if !hasGraphQLPost(rodGot) {
		t.Fatalf("rod backend did not capture the SPA fetch /graphql POST (LAB-1535 not closed); got %d requests: %v",
			len(rodGot), urlList(rodGot))
	}

	// HTTP backend: expected to MISS the runtime fetch (no JS execution).
	// This is a documented capability gap — fail loudly if the assumption changes.
	httpCrawler := NewCrawler(CrawlerOptions{
		Depth:        1,
		MaxPages:     10,
		Timeout:      30 * time.Second,
		Scope:        "same-origin",
		Headless:     false,
		AllowPrivate: true,
	})
	httpGot, _ := httpCrawler.Crawl(context.Background(), srv.URL)
	if hasGraphQLPost(httpGot) {
		t.Errorf("HTTPCrawler unexpectedly captured a runtime fetch POST — capability gap assumption changed; update docs/benchmarks/crawler-comparison.md")
	}
}

// hasGraphQLPost reports whether any captured request is a POST to a path
// ending with "/graphql". It is method+path agnostic w.r.t. Source so it
// works for both "http" and "browser" source values.
func hasGraphQLPost(reqs []ObservedRequest) bool {
	for _, r := range reqs {
		if r.Method == "POST" && strings.HasSuffix(r.URL, "/graphql") {
			return true
		}
	}
	return false
}

// urlList returns a human-readable list of URLs in reqs for test failure messages.
func urlList(reqs []ObservedRequest) []string {
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Method+" "+r.URL)
	}
	return out
}
