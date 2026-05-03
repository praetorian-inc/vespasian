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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/pkg/ssrf"
)

// allowLocal returns a config that disables SSRF protection so tests can
// hit httptest's 127.0.0.1 listeners. It also sets TargetURL so the
// same-origin gate accepts the test server's host.
func allowLocal(srv *httptest.Server) JSReplayConfig {
	return JSReplayConfig{
		Client:       srv.Client(),
		TargetURL:    srv.URL,
		AllowPrivate: true,
	}
}

func TestExtractAPIPaths(t *testing.T) {
	tests := []struct {
		name string
		js   string
		want []string
	}{
		{
			name: "service prefix concatenation (crAPI-style)",
			js: `
				var IDENTITY="identity/"+"api/auth/login";
				fetch("workshop/"+"api/shop/products");
				var d="community/api/v2/community/posts/recent";
				var f="identity/api/v2/user/dashboard";
			`,
			want: []string{
				"/community/api/v2/community/posts/recent",
				"/identity/api/auth/login",
				"/identity/api/shop/products",
				"/identity/api/v2/user/dashboard",
				"/workshop/api/auth/login",
				"/workshop/api/shop/products",
			},
		},
		{
			name: "simple quoted API paths",
			js: `
				fetch("/api/v2/users");
				url: "/api/v1/items",
				path: "/rest/data/query",
				rpc: "/rpc/method",
			`,
			want: []string{
				"/api/v1/items",
				"/api/v2/users",
				"/rest/data/query",
				"/rpc/method",
			},
		},
		{
			name: "template literals",
			js: "const url = `/api/v2/users/${userId}/profile`;\n" +
				"const other = `/v1/items/${id}`;\n",
			want: []string{
				"/api/v2/users/{param}/profile",
				"/v1/items/{param}",
			},
		},
		{
			name: "full URLs",
			js: `
				const base = "https://api.example.com/v2/users/list";
				fetch('http://backend:8080/api/v1/data/query');
			`,
			want: []string{
				"http://backend:8080/api/v1/data/query",
				"https://api.example.com/v2/users/list",
			},
		},
		{
			name: "paths with parameters",
			js: `
				"/api/v2/user/videos/{video_id}"
				"/api/v2/vehicle/{vehicleId}/location"
			`,
			want: []string{
				"/api/v2/user/videos/{video_id}",
				"/api/v2/vehicle/{vehicleId}/location",
			},
		},
		{
			name: "graphql endpoint",
			js: `
				fetch("/graphql", {method: "POST"});
				url: "/api/graphql/query",
			`,
			want: []string{
				"/api/graphql/query",
				"/graphql",
			},
		},
		{
			name: "skip static files",
			js: `
				"/api/bundle.js"
				"/api/styles.css"
				"/api/source.map"
				"/api/v2/real-endpoint"
			`,
			want: []string{"/api/v2/real-endpoint"},
		},
		{
			name: "no API paths",
			js:   `var x = "hello world"; var y = "/static/image.png";`,
			want: nil,
		},
		{
			name: "deduplication across strategies",
			js: `
				"/api/v2/users"
				'/api/v2/users'
			` + "`/api/v2/users`",
			want: []string{"/api/v2/users"},
		},
		{
			name: "no prefixes — paths kept as-is",
			js: `
				fetch("/api/v2/data");
				fetch("/v1/items");
			`,
			want: []string{
				"/api/v2/data",
				"/v1/items",
			},
		},
		{
			name: "mixed strategies",
			js: `
				"identity/"+"api/auth/login"
				'/api/v2/public/health'
			` + "`/v1/metrics/${env}`" + `
				"https://ext.example.com/api/v1/webhook"
			`,
			want: []string{
				// Paths without an inline prefix get combined with the
				// discovered prefix "identity/". The template literal
				// `/v1/metrics/${env}` is reconstructed as
				// /v1/metrics/{param} by the walker.
				"/identity/api/auth/login",
				"/identity/api/v2/public/health",
				"/identity/v1/metrics/{param}",
				"https://ext.example.com/api/v1/webhook",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAPIPaths([]byte(tt.js), nil)
			sort.Strings(got)
			sort.Strings(tt.want)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractAPIPaths_TemplateLiteralInterpolation(t *testing.T) {
	// Regression test for REQ-001: template literals with ${...} interpolations
	// must reconstruct the literal segments after the placeholder, not stop
	// at the first ${.
	js := "const url = `/api/users/${id}/profile`;\n" +
		"const nested = `/api/v2/items/${itemId}/comments/${commentId}`;\n"

	got := extractAPIPaths([]byte(js), nil)
	sort.Strings(got)

	assert.Equal(t, []string{
		"/api/users/{param}/profile",
		"/api/v2/items/{param}/comments/{param}",
	}, got)
}

func TestExtractServicePrefixes(t *testing.T) {
	tests := []struct {
		name string
		js   string
		want []string
	}{
		{
			name: "crAPI-style",
			js:   `"identity/"+"api/auth/login"; "workshop/"+"api/shop/products"; "community/"+"v2/posts"`,
			want: []string{"identity/", "workshop/", "community/"},
		},
		{
			name: "no concatenation",
			js:   `"/api/v2/users"; "/identity/api/auth/login"`,
			want: nil,
		},
		{
			name: "deduplication",
			js:   `"identity/"+"api/a"; "identity/"+"api/b"`,
			want: []string{"identity/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractServicePrefixes([]byte(tt.js), nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractServicePrefixes_FromCrawlResults(t *testing.T) {
	requests := []ObservedRequest{
		{URL: "https://example.com/static/js/main.js", Source: "katana"},
		{URL: "https://example.com/static/js/identity/", Source: "https://example.com/static/js/main.js"},
		{URL: "https://example.com/static/js/workshop/", Source: "https://example.com/static/js/main.js"},
		{URL: "https://example.com/static/js/community/", Source: "https://example.com/static/js/main.js"},
		// Not a prefix: too deep.
		{URL: "https://example.com/static/js/some/nested/", Source: "https://example.com/static/js/main.js"},
		// Not from a JS file.
		{URL: "https://example.com/other/", Source: "https://example.com/page.html"},
	}

	prefixes := extractServicePrefixes(nil, requests)
	sort.Strings(prefixes)
	assert.Equal(t, []string{"community/", "identity/", "workshop/"}, prefixes)
}

func TestExtractAPIPaths_WithCrawlPrefixes(t *testing.T) {
	js := `"api/auth/login" "api/shop/products" "identity/api/v2/user/dashboard"`
	requests := []ObservedRequest{
		{URL: "https://example.com/static/js/main.js", Source: "katana"},
		{URL: "https://example.com/static/js/identity/", Source: "https://example.com/static/js/main.js"},
		{URL: "https://example.com/static/js/workshop/", Source: "https://example.com/static/js/main.js"},
	}

	got := extractAPIPaths([]byte(js), requests)
	sort.Strings(got)
	assert.Equal(t, []string{
		"/identity/api/auth/login",
		"/identity/api/shop/products",
		"/identity/api/v2/user/dashboard",
		"/workshop/api/auth/login",
		"/workshop/api/shop/products",
	}, got)
}

func TestIsJSResponse(t *testing.T) {
	assert.True(t, isJSResponse("application/javascript"))
	assert.True(t, isJSResponse("text/javascript"))
	assert.True(t, isJSResponse("application/javascript; charset=utf-8"))
	assert.False(t, isJSResponse("text/html"))
	assert.False(t, isJSResponse("application/json"))
	assert.False(t, isJSResponse(""))
}

func TestIsJSURL(t *testing.T) {
	assert.True(t, isJSURL("https://example.com/app.js"))
	assert.True(t, isJSURL("https://example.com/main.8c78208c.js"))
	assert.True(t, isJSURL("https://example.com/module.mjs"))
	assert.False(t, isJSURL("https://example.com/page.html"))
	assert.False(t, isJSURL("https://example.com/api/data"))
}

func TestHasInlinePrefix(t *testing.T) {
	assert.True(t, hasInlinePrefix("identity/api/auth/login"))
	assert.True(t, hasInlinePrefix("community/v2/posts"))
	assert.False(t, hasInlinePrefix("api/auth/login"))
	assert.False(t, hasInlinePrefix("v2/users"))
	// Regression: iter-7 found apiIndicators only listed v1-v4 even though
	// the extraction regexes accept v[1-9][0-9]*. Iter-8 unified them via
	// apiIndicatorPattern. These cases lock in v5+ classification so a
	// regression that re-narrows the alternation to v[1-4] would fail.
	assert.True(t, hasInlinePrefix("billing/v5/invoices"))
	assert.True(t, hasInlinePrefix("payments/v9/refunds"))
	assert.True(t, hasInlinePrefix("legacy/v42/users"))
	assert.False(t, hasInlinePrefix("v5/invoices"))
	assert.False(t, hasInlinePrefix("v42/users"))
}

func TestHasAPIIndicator(t *testing.T) {
	// Exercises apiIndicatorPattern across the full v[1-9][0-9]* range plus
	// every other alternation branch (api/, rest/, rpc/, graphql) so a
	// future re-narrowing of the alternation is caught directly.
	for _, s := range []string{
		"/api/auth/login", "/v1/users", "/v2/items", "/v5/orders",
		"/v9/refunds", "/v42/legacy", "/rest/data/query", "/rpc/method",
		"/graphql",
	} {
		assert.True(t, hasAPIIndicator(s), "expected %q to be classified as API indicator", s)
	}
	for _, s := range []string{"/static/image.png", "/assets/lib.js", "v0/zero"} {
		assert.False(t, hasAPIIndicator(s), "expected %q NOT to be classified as API indicator", s)
	}
}

func TestJSReplayConfig_WithDefaults(t *testing.T) {
	t.Run("zero values get defaults", func(t *testing.T) {
		cfg := JSReplayConfig{AllowPrivate: true}.withDefaults()
		assert.Equal(t, 10*time.Second, cfg.Timeout)
		assert.Equal(t, 500, cfg.MaxEndpoints)
		assert.NotNil(t, cfg.Client)
		assert.Equal(t, io.Discard, cfg.Stderr)
		// MaxTotalTime should be capped to 10 minutes max.
		assert.Equal(t, 10*time.Minute, cfg.MaxTotalTime)

		// CheckRedirect must return ErrUseLastResponse to prevent automatic
		// redirect following (we want to record what each URL actually returns).
		err := cfg.Client.CheckRedirect(nil, nil)
		assert.True(t, errors.Is(err, http.ErrUseLastResponse), "CheckRedirect must return http.ErrUseLastResponse")
	})

	t.Run("non-zero values preserved", func(t *testing.T) {
		cfg := JSReplayConfig{
			Timeout:      5 * time.Second,
			MaxEndpoints: 7,
			MaxTotalTime: time.Minute,
			AllowPrivate: true,
		}.withDefaults()
		assert.Equal(t, 5*time.Second, cfg.Timeout)
		assert.Equal(t, 7, cfg.MaxEndpoints)
		assert.Equal(t, time.Minute, cfg.MaxTotalTime)
	})

	t.Run("MaxTotalTime derived from MaxEndpoints*Timeout when small", func(t *testing.T) {
		cfg := JSReplayConfig{
			MaxEndpoints: 3,
			Timeout:      2 * time.Second,
			AllowPrivate: true,
		}.withDefaults()
		assert.Equal(t, 6*time.Second, cfg.MaxTotalTime)
	})
}

func TestReplayJSExtracted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/v2/user/dashboard":
			if r.Header.Get("Authorization") != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name":"Test User"}`)) //nolint:errcheck,gosec // test handler
		case "/workshop/api/shop/products":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"id":1}]`)) //nolint:errcheck,gosec // test handler
		default:
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html>SPA</html>")) //nolint:errcheck,gosec // test handler
		}
	}))
	defer srv.Close()

	jsBody := []byte(`
		"identity/"+"api/v2/user/dashboard"
		"workshop/"+"api/shop/products"
	`)

	requests := []ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/",
			Source: "katana",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte("<html>...</html>"),
			},
		},
		{
			Method: "GET",
			URL:    srv.URL + "/static/js/main.js",
			Source: srv.URL + "/",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        jsBody,
			},
		},
	}

	cfg := allowLocal(srv)
	cfg.Headers = map[string]string{"Authorization": "Bearer test-token"}

	result := ReplayJSExtracted(context.Background(), requests, cfg)

	// Original requests preserved.
	require.GreaterOrEqual(t, len(result), 2)

	// Collect appended URLs.
	appended := make(map[string]ObservedRequest)
	for _, req := range result[2:] {
		appended[req.URL] = req
	}

	dashboard, ok := appended[srv.URL+"/identity/api/v2/user/dashboard"]
	require.True(t, ok, "expected dashboard endpoint")
	assert.Equal(t, "GET", dashboard.Method)
	assert.Equal(t, http.StatusOK, dashboard.Response.StatusCode)
	assert.Equal(t, "application/json", dashboard.Response.ContentType)
	assert.Contains(t, string(dashboard.Response.Body), "Test User")
	assert.Equal(t, "js-extract", dashboard.Source)
	assert.Equal(t, "Bearer test-token", dashboard.Headers["Authorization"],
		"same-origin probes must record forwarded auth headers")

	products, ok := appended[srv.URL+"/workshop/api/shop/products"]
	require.True(t, ok, "expected products endpoint")
	assert.Equal(t, "GET", products.Method)
	assert.Equal(t, http.StatusOK, products.Response.StatusCode)
	assert.Equal(t, "application/json", products.Response.ContentType)
}

func TestReplayJSExtracted_FullURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	// JS contains a full URL pointing to our test server (same origin as TargetURL).
	jsBody := []byte(`const url = "` + srv.URL + `/api/v1/health";`)

	requests := []ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/app.js",
			Source: "katana",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        jsBody,
			},
		},
	}

	cfg := allowLocal(srv)
	result := ReplayJSExtracted(context.Background(), requests, cfg)

	require.Len(t, result, 2)
	assert.Equal(t, srv.URL+"/api/v1/health", result[1].URL)
	assert.Equal(t, "application/json", result[1].Response.ContentType)
}

func TestReplayJSExtracted_SkipsCrossOriginByDefault(t *testing.T) {
	// Off-target server which would record any incoming request (including
	// any forwarded auth headers). Test asserts no request reaches it.
	hits := 0
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec // test handler
	}))
	defer off.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	jsBody := []byte(`const u = "` + off.URL + `/api/v1/exfil";`)

	requests := []ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/app.js",
			Source: "katana",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        jsBody,
			},
		},
	}

	cfg := allowLocal(srv)
	cfg.Headers = map[string]string{"Authorization": "Bearer secret"}

	result := ReplayJSExtracted(context.Background(), requests, cfg)
	// Original request preserved, cross-origin URL dropped.
	assert.Len(t, result, 1)
	assert.Equal(t, 0, hits, "cross-origin URL must not be probed by default")
}

func TestReplayJSExtracted_AllowCrossOriginOptIn(t *testing.T) {
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec // test handler
	}))
	defer off.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	jsBody := []byte(`const u = "` + off.URL + `/api/v1/data";`)

	requests := []ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/app.js",
			Source: "katana",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        jsBody,
			},
		},
	}

	cfg := allowLocal(srv)
	cfg.AllowCrossOrigin = true
	result := ReplayJSExtracted(context.Background(), requests, cfg)
	assert.Len(t, result, 2, "AllowCrossOrigin should let cross-origin URLs through")
}

func TestReplayJSExtracted_NoJSFiles(t *testing.T) {
	original := ObservedRequest{
		Method:   "GET",
		URL:      "https://example.com/",
		Source:   "katana",
		Response: ObservedResponse{StatusCode: 200, ContentType: "text/html"},
	}
	requests := []ObservedRequest{original}
	result := ReplayJSExtracted(context.Background(), requests, JSReplayConfig{AllowPrivate: true})
	require.Len(t, result, 1)
	// TEST-006: assert the original request is returned verbatim.
	assert.Equal(t, original, result[0])
}

func TestReplayJSExtracted_EmptyInput(t *testing.T) {
	t.Run("nil slice", func(t *testing.T) {
		var stderr bytes.Buffer
		result := ReplayJSExtracted(context.Background(), nil, JSReplayConfig{AllowPrivate: true, Verbose: true, Stderr: &stderr})
		assert.Empty(t, result)
		assert.Empty(t, stderr.Bytes(), "no log output expected for empty input")
	})
	t.Run("empty slice", func(t *testing.T) {
		var stderr bytes.Buffer
		result := ReplayJSExtracted(context.Background(), []ObservedRequest{}, JSReplayConfig{AllowPrivate: true, Verbose: true, Stderr: &stderr})
		assert.Empty(t, result)
		assert.Empty(t, stderr.Bytes())
	})
	t.Run("requests with empty URLs", func(t *testing.T) {
		input := []ObservedRequest{
			{Method: "GET", URL: ""},
			{Method: "GET", URL: ""},
		}
		var stderr bytes.Buffer
		result := ReplayJSExtracted(context.Background(), input, JSReplayConfig{AllowPrivate: true, Verbose: true, Stderr: &stderr})
		assert.Equal(t, input, result, "input should be returned unchanged when no baseURL discoverable")
		// No logging means we exited via the targetOrigin == "" early return,
		// not because we reached the path-extraction or probe loops.
		assert.Empty(t, stderr.Bytes(), "early return must skip extraction and probe phases")
	})
}

func TestReplayJSExtracted_MaxEndpoints(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	jsBody := []byte(`
		"/api/v1/a" "/api/v1/b" "/api/v1/c" "/api/v1/d" "/api/v1/e"
	`)

	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      srv.URL + "/app.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: jsBody},
		},
	}

	cfg := allowLocal(srv)
	cfg.MaxEndpoints = 2
	result := ReplayJSExtracted(context.Background(), requests, cfg)

	// TEST-007: exact equality. With deterministic sorting, we can predict
	// the output: 1 original + exactly 2 probed; exactly 2 server hits.
	assert.Equal(t, 3, len(result))
	assert.Equal(t, 2, callCount)
}

func TestReplayJSExtracted_MaxEndpointsCountsAllAttempts(t *testing.T) {
	// QUAL-005: MaxEndpoints must cap probe attempts, not just successful
	// results. A handler that always 404s should still be probed at most
	// MaxEndpoints times.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	jsBody := []byte(`"/api/v1/a" "/api/v1/b" "/api/v1/c" "/api/v1/d" "/api/v1/e"`)
	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      srv.URL + "/app.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: jsBody},
		},
	}

	cfg := allowLocal(srv)
	cfg.MaxEndpoints = 3
	ReplayJSExtracted(context.Background(), requests, cfg)
	assert.Equal(t, 3, hits, "MaxEndpoints must cap probe attempts even when all return 404")
}

func TestReplayJSExtracted_DeterministicProbeOrder(t *testing.T) {
	// QUAL-007: with MaxEndpoints < paths-found, the same set of paths must
	// be probed across runs. We verify this by running ReplayJSExtracted
	// multiple times and comparing the recorded URLs.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	jsBody := []byte(`"/api/v1/a" "/api/v1/b" "/api/v1/c" "/api/v1/d" "/api/v1/e"`)
	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      srv.URL + "/app.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: jsBody},
		},
	}

	cfg := allowLocal(srv)
	cfg.MaxEndpoints = 2

	collect := func() []string {
		result := ReplayJSExtracted(context.Background(), requests, cfg)
		var probed []string
		for _, r := range result {
			if r.Source == "js-extract" {
				probed = append(probed, r.URL)
			}
		}
		sort.Strings(probed)
		return probed
	}

	first := collect()
	for i := 0; i < 4; i++ {
		assert.Equal(t, first, collect(), "probe set must be deterministic")
	}
}

func TestReplayJSExtracted_Filters404(t *testing.T) {
	// TEST-004: paths that 404 must be dropped; 200 paths must be appended.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workshop/api/products":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`)) //nolint:errcheck,gosec // test handler
		case "/identity/api/products":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	jsBody := []byte(`"identity/"+"api/products"; "workshop/"+"api/products"`)
	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      srv.URL + "/app.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: jsBody},
		},
	}

	cfg := allowLocal(srv)
	result := ReplayJSExtracted(context.Background(), requests, cfg)

	var jsExtracted []string
	for _, r := range result {
		if r.Source == "js-extract" {
			jsExtracted = append(jsExtracted, r.URL)
		}
	}
	assert.Equal(t, []string{srv.URL + "/workshop/api/products"}, jsExtracted,
		"only the 200-returning path should be appended")
}

// errRoundTripper always returns the configured error from RoundTrip.
type errRoundTripper struct{ err error }

func (e errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

func TestReplayJSExtracted_ProbeNetworkError(t *testing.T) {
	// When probeURL returns nil (network failure), the path is silently
	// dropped — original requests are preserved unchanged. This test uses
	// an always-erroring RoundTripper instead of a closed server, so it is
	// deterministic regardless of port-reuse or kernel TCP behavior.
	cfg := JSReplayConfig{
		Client:       &http.Client{Transport: errRoundTripper{err: errors.New("simulated network failure")}},
		TargetURL:    "http://example.com",
		AllowPrivate: true,
		Timeout:      500 * time.Millisecond,
	}

	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      "http://example.com/app.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: []byte(`"/api/v1/data"`)},
		},
	}

	result := ReplayJSExtracted(context.Background(), requests, cfg)
	assert.Equal(t, requests, result, "probe failures must leave the original requests unchanged")
}

func TestReplayJSExtracted_ContextCancellation(t *testing.T) {
	// TEST-008: canceled context must short-circuit before any probe is
	// attempted.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	original := ObservedRequest{
		Method:   "GET",
		URL:      srv.URL + "/app.js",
		Source:   "katana",
		Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: []byte(`"/api/v2/data"`)},
	}
	requests := []ObservedRequest{original}

	result := ReplayJSExtracted(ctx, requests, allowLocal(srv))
	require.Len(t, result, 1)
	assert.Equal(t, original, result[0], "cancellation must preserve original request")
	assert.Equal(t, 0, hits, "no probes should be attempted with a canceled context")
}

func TestReplayJSExtracted_TruncatedBody(t *testing.T) {
	fullJS := make([]byte, MaxResponseBodySize+100)
	copy(fullJS, []byte(`/* padding */`))
	copy(fullJS[MaxResponseBodySize+10:], []byte(`"/api/v2/hidden"`))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(fullJS) //nolint:errcheck,gosec // test handler
		case "/api/v2/hidden":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"found":true}`)) //nolint:errcheck,gosec // test handler
		}
	}))
	defer srv.Close()

	truncated := make([]byte, MaxResponseBodySize)
	copy(truncated, fullJS[:MaxResponseBodySize])

	requests := []ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/app.js",
			Source: "katana",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        truncated,
			},
		},
	}

	cfg := allowLocal(srv)
	result := ReplayJSExtracted(context.Background(), requests, cfg)

	require.Len(t, result, 2)
	assert.Equal(t, srv.URL+"/api/v2/hidden", result[1].URL)
	assert.Equal(t, "application/json", result[1].Response.ContentType)
}

func TestReplayJSExtracted_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`var endpoint = "/api/v1/users";`)) //nolint:errcheck,gosec // test handler
		case "/api/v1/users":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"id":1}]`)) //nolint:errcheck,gosec // test handler
		}
	}))
	defer srv.Close()

	requests := []ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/app.js",
			Source: "katana",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        nil,
			},
		},
	}

	cfg := allowLocal(srv)
	result := ReplayJSExtracted(context.Background(), requests, cfg)

	require.Len(t, result, 2)
	assert.Equal(t, srv.URL+"/api/v1/users", result[1].URL)
	assert.Equal(t, "js-extract", result[1].Source)
	assert.Equal(t, "application/json", result[1].Response.ContentType)
}

func TestExtractScriptURLs(t *testing.T) {
	html := []byte(`<!DOCTYPE html>
<html>
<head>
<script src="main.js"></script>
<script src="/assets/public/app.js"></script>
<script src="https://cdn.example.com/lib.js"></script>
</head>
</html>`)

	urls := extractScriptURLs(html, "http://localhost:3000/")
	assert.Contains(t, urls, "http://localhost:3000/main.js")
	assert.Contains(t, urls, "http://localhost:3000/assets/public/app.js")
	assert.Contains(t, urls, "https://cdn.example.com/lib.js")
	assert.Len(t, urls, 3)
}

func TestExtractScriptURLs_Deduplicates(t *testing.T) {
	html := []byte(`<script src="main.js"></script><script src="main.js"></script>`)
	urls := extractScriptURLs(html, "http://localhost:3000/")
	assert.Len(t, urls, 1)
}

func TestExtractScriptURLs_InvalidPageURL(t *testing.T) {
	// TEST-002: pageURL that url.Parse rejects should produce a nil result
	// rather than silently using an empty base.
	html := []byte(`<script src="main.js"></script>`)
	// A control byte in the URL forces url.Parse to return an error.
	urls := extractScriptURLs(html, "http://example.com/\x00bad")
	assert.Nil(t, urls)
}

func TestLooksLikeHTML(t *testing.T) {
	assert.True(t, looksLikeHTML([]byte(`<!DOCTYPE html><html>`)))
	assert.True(t, looksLikeHTML([]byte(`<html lang="en">`)))
	assert.True(t, looksLikeHTML([]byte("  \n  <!doctype html>")))
	assert.False(t, looksLikeHTML([]byte(`var x = "/api/v1/users";`)))
	assert.False(t, looksLikeHTML([]byte(`(function(){`)))
	assert.False(t, looksLikeHTML(nil))
	assert.False(t, looksLikeHTML([]byte("")))
}

func TestFetchJSBody_RejectsHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><body>SPA</body></html>`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	cfg := allowLocal(srv).withDefaults()
	body := fetchJSBody(context.Background(), cfg, srv.URL+"/nonexistent.js", srv.URL)
	assert.Nil(t, body, "fetchJSBody should return nil for HTML responses")
}

func TestFetchJSBody_RejectsHTMLWithoutContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<!DOCTYPE html><html><body>SPA</body></html>`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	cfg := allowLocal(srv).withDefaults()
	body := fetchJSBody(context.Background(), cfg, srv.URL+"/nonexistent.js", srv.URL)
	assert.Nil(t, body, "fetchJSBody should detect HTML from body even without Content-Type")
}

func TestFetchJSBody_RejectsErrorStatus(t *testing.T) {
	// TEST-005: a server returning 4xx/5xx with a non-HTML body must be
	// rejected by the status guard.
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write([]byte(`{"error":"boom"}`)) //nolint:errcheck,gosec // test handler
		}))
		cfg := allowLocal(srv).withDefaults()
		body := fetchJSBody(context.Background(), cfg, srv.URL+"/missing.js", srv.URL)
		assert.Nil(t, body, "fetchJSBody must reject status %d", status)
		srv.Close()
	}
}

func TestFetchJSBody_SkipsCrossOriginByDefault(t *testing.T) {
	// SEC-BE-006: cross-origin script srcs should not be re-fetched, since
	// that would carry the user's auth headers off-target.
	hits := 0
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`var x = "/api/v1/leak";`)) //nolint:errcheck,gosec // test handler
	}))
	defer off.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	cfg := allowLocal(srv).withDefaults()
	body := fetchJSBody(context.Background(), cfg, off.URL+"/cdn.js", srv.URL)
	assert.Nil(t, body, "cross-origin JS fetches must be blocked unless AllowCrossOrigin is true")
	assert.Equal(t, 0, hits, "no request should reach the cross-origin host")
}

func TestReplayJSExtracted_HTMLScriptDiscovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`var api = "/api/v1/products"; var other = "/rest/user/login";`)) //nolint:errcheck,gosec // test handler
		case "/api/v1/products":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"data":[]}`)) //nolint:errcheck,gosec // test handler
		case "/rest/user/login":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok"}`)) //nolint:errcheck,gosec // test handler
		default:
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!DOCTYPE html><html><head><script src="main.js"></script></head></html>`)) //nolint:errcheck,gosec // test handler
		}
	}))
	defer srv.Close()

	requests := []ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/",
			Source: "katana",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte(`<!DOCTYPE html><html><head><script src="main.js"></script></head></html>`),
			},
		},
		{
			Method: "GET",
			URL:    srv.URL + "/text/assets/main.js",
			Source: "katana",
			Response: ObservedResponse{
				StatusCode: 200,
				Body:       nil,
			},
		},
	}

	cfg := allowLocal(srv)
	result := ReplayJSExtracted(context.Background(), requests, cfg)

	var apiURLs []string
	for _, r := range result {
		if r.Source == "js-extract" {
			apiURLs = append(apiURLs, r.URL)
		}
	}
	assert.Contains(t, apiURLs, srv.URL+"/api/v1/products")
	assert.Contains(t, apiURLs, srv.URL+"/rest/user/login")
}

func TestAddPath_RejectsURLCredentials(t *testing.T) {
	// SEC-BE-003: full URLs with embedded credentials must be dropped.
	js := []byte(`"http://user:pass@evil.example.com/api/v1/exfil"`)
	got := extractAPIPaths(js, nil)
	assert.Empty(t, got, "URL with embedded credentials must be rejected")
}

func TestAddPath_RejectsNonHTTPScheme(t *testing.T) {
	// validateFullURL must reject non-http(s) schemes when they sneak in
	// via the full-URL pattern.
	cases := []string{
		"file:///etc/passwd",
		"ftp://example.com/api/v1/data",
		"javascript://api/v2/x",
	}
	for _, raw := range cases {
		_, ok := validateFullURL(raw)
		assert.False(t, ok, "validateFullURL must reject %s", raw)
	}
}

func TestReplayJSExtracted_RejectsPrivateIPWhenSSRFEnforced(t *testing.T) {
	// SEC-BE-004: when AllowPrivate is false (the default), URLs resolving
	// to private/loopback IPs must be skipped before any HTTP request is
	// made.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	// JS contains a full URL pointing at the loopback test server, but the
	// scan target is a public host. With AllowPrivate=false, the SSRF
	// guard must drop the URL.
	jsBody := []byte(`const u = "` + srv.URL + `/api/v1/internal";`)
	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      "https://example.com/app.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: jsBody},
		},
	}

	cfg := JSReplayConfig{
		Client:           srv.Client(),
		TargetURL:        "https://example.com/",
		AllowPrivate:     false,
		AllowCrossOrigin: true, // bypass same-origin to isolate SSRF behavior
	}
	result := ReplayJSExtracted(context.Background(), requests, cfg)
	assert.Equal(t, requests, result, "private IP must be dropped when SSRF is enforced")
	assert.Equal(t, 0, hits, "no request must reach a private IP under SSRF protection")
}

func TestReplayJSExtracted_DefensivelyCopiesHeaders(t *testing.T) {
	// SEC-BE-008: subsequent mutations to cfg.Headers must not leak into
	// already-recorded results.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	headers := map[string]string{"Authorization": "Bearer initial"}
	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      srv.URL + "/app.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: []byte(`"/api/v1/data"`)},
		},
	}

	cfg := allowLocal(srv)
	cfg.Headers = headers
	result := ReplayJSExtracted(context.Background(), requests, cfg)
	require.Len(t, result, 2)

	// Mutate the original headers map after recording — recorded entry must
	// not be affected.
	headers["Authorization"] = "Bearer mutated"
	delete(headers, "Authorization")
	assert.Equal(t, "Bearer initial", result[1].Headers["Authorization"])
}

func TestReplayJSExtracted_DoesNotForwardHeadersCrossOrigin(t *testing.T) {
	// SEC-BE-002: when AllowCrossOrigin is true and a cross-origin URL is
	// probed, the user's headers must not be forwarded.
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo received headers so the test can verify Authorization absence.
		auth := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if auth != "" {
			w.Write([]byte(`{"saw":"` + auth + `"}`)) //nolint:errcheck,gosec // test handler
			return
		}
		w.Write([]byte(`{"saw":""}`)) //nolint:errcheck,gosec // test handler
	}))
	defer off.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	jsBody := []byte(`const u = "` + off.URL + `/api/v1/echo";`)
	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      srv.URL + "/app.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: jsBody},
		},
	}

	cfg := allowLocal(srv)
	cfg.AllowCrossOrigin = true
	cfg.Headers = map[string]string{"Authorization": "Bearer secret"}

	result := ReplayJSExtracted(context.Background(), requests, cfg)
	require.Len(t, result, 2)
	assert.Contains(t, string(result[1].Response.Body), `"saw":""`,
		"cross-origin probe must not carry user-supplied auth headers")
}

func TestSanitizeForLog(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"hello", `"hello"`},
		{"abc\x1b[31mevil", `"abc\x1b[31mevil"`},
		{"line\nbreak", `"line\nbreak"`},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, sanitizeForLog(tc.in))
	}
}

func TestMatchesContentType(t *testing.T) {
	assert.True(t, matchesContentType("application/json; charset=utf-8", []string{"application/json"}))
	assert.True(t, matchesContentType("APPLICATION/JSON", []string{"application/json"}))
	assert.False(t, matchesContentType("text/plain", []string{"application/json"}))
	assert.False(t, matchesContentType("", []string{"application/json"}))
}

func TestIsSameOrigin(t *testing.T) {
	target := "https://example.com:8443"
	assert.True(t, isSameOrigin("https://example.com:8443/api/v1/x", target))
	assert.False(t, isSameOrigin("https://example.com/api/v1/x", target), "different port = different origin")
	assert.False(t, isSameOrigin("http://example.com:8443/api/v1/x", target), "different scheme = different origin")
	assert.False(t, isSameOrigin("https://other.example.com/api", target))
	assert.False(t, isSameOrigin("not a url", target))
	assert.False(t, isSameOrigin("https://example.com/api/v1/x", ""))
}

func TestOriginOf(t *testing.T) {
	assert.Equal(t, "https://example.com", originOf("https://example.com/api"))
	assert.Equal(t, "https://example.com:8443", originOf("https://example.com:8443/x"))
	assert.Equal(t, "", originOf("not a url"))
	assert.Equal(t, "", originOf("/relative/path"))
}

func TestExtractAPIPaths_CleanPathPassesThrough(t *testing.T) {
	// Sanity check that a clean quoted path is extracted and parses as a
	// valid URL. Sanitization of attacker-controlled control characters is
	// the log layer's responsibility (see TestSanitizeForLog).
	js := []byte(`"/api/v2/data"`)
	got := extractAPIPaths(js, nil)
	assert.Equal(t, []string{"/api/v2/data"}, got)
	_, err := url.Parse(got[0])
	assert.NoError(t, err)
}

// --- TEST-001: withDefaults SSRF transport ---

func TestJSReplayConfig_WithDefaults_InstallsSSRFTransport(t *testing.T) {
	// When AllowPrivate is false and no client is supplied, withDefaults must
	// install ssrf.SafeDialContext on the transport. We assert by attempting a
	// loopback dial through the resulting client and expecting an SSRF block.
	cfg := JSReplayConfig{}.withDefaults()
	transport, ok := cfg.Client.Transport.(*http.Transport)
	require.True(t, ok, "default transport must be *http.Transport")
	require.NotNil(t, transport.DialContext, "DialContext must be set when !AllowPrivate")
	_, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	require.Error(t, err, "DialContext must reject loopback under SSRF protection")
	assert.Contains(t, err.Error(), "private")
}

func TestJSReplayConfig_WithDefaults_AllowPrivateBypassesDialer(t *testing.T) {
	// With AllowPrivate, withDefaults must NOT install ssrf.SafeDialContext.
	// Compare function pointers via reflect: if our SafeDialContext was
	// installed, the pointer would equal ssrf.SafeDialContext's.
	cfg := JSReplayConfig{AllowPrivate: true}.withDefaults()
	transport, ok := cfg.Client.Transport.(*http.Transport)
	require.True(t, ok)
	if transport.DialContext != nil {
		gotPtr := reflect.ValueOf(transport.DialContext).Pointer()
		ssrfPtr := reflect.ValueOf(ssrf.SafeDialContext).Pointer()
		assert.NotEqual(t, ssrfPtr, gotPtr,
			"AllowPrivate=true must NOT install ssrf.SafeDialContext")
	}
	// And confirm a loopback dial through the resulting client is NOT
	// blocked by our SSRF guard. (It may still fail because port 1 is
	// closed — the test asserts the error is NOT the SSRF "private IP"
	// error our guard would produce.)
	_, err := cfg.Client.Get("http://127.0.0.1:1/")
	if err != nil {
		assert.NotContains(t, err.Error(), "blocked private",
			"AllowPrivate=true must not produce SSRF blocking errors")
	}
}

func TestJSReplayConfig_WithDefaults_WrapsCallerSuppliedClient(t *testing.T) {
	// Even when the caller supplies their own *http.Client, withDefaults must
	// install ssrf.SafeDialContext on that client's transport so the dial-time
	// SSRF check (DNS-rebinding mitigation) is preserved.
	caller := &http.Client{Transport: &http.Transport{}}
	cfg := JSReplayConfig{Client: caller}.withDefaults()
	t2, ok := cfg.Client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, t2.DialContext, "caller-supplied transport must be wrapped with SSRF dialer")
	_, err := t2.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	require.Error(t, err, "wrapped DialContext must reject loopback")
}

// --- TEST-002: isHTMLResponse content-type coverage ---

func TestIsHTMLResponse(t *testing.T) {
	assert.True(t, isHTMLResponse("text/html"))
	assert.True(t, isHTMLResponse("text/html; charset=utf-8"))
	assert.True(t, isHTMLResponse("application/xhtml+xml"))
	assert.True(t, isHTMLResponse("application/xhtml+xml; charset=utf-8"))
	assert.True(t, isHTMLResponse("TEXT/HTML"))
	assert.False(t, isHTMLResponse("application/json"))
	assert.False(t, isHTMLResponse(""))
}

// --- TEST-003: copyHeaders direct ---

func TestCopyHeaders(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		assert.Nil(t, copyHeaders(nil))
	})
	t.Run("empty", func(t *testing.T) {
		got := copyHeaders(map[string]string{})
		require.NotNil(t, got)
		assert.Empty(t, got)
	})
	t.Run("populated", func(t *testing.T) {
		orig := map[string]string{"Authorization": "Bearer x", "X-Foo": "bar"}
		got := copyHeaders(orig)
		assert.Equal(t, orig, got)
		// Mutating the original must not affect the copy and vice-versa.
		orig["Authorization"] = "Bearer mutated"
		orig["NewKey"] = "added"
		assert.Equal(t, "Bearer x", got["Authorization"])
		_, hasNew := got["NewKey"]
		assert.False(t, hasNew, "new keys in original must not appear in copy")
	})
}

// --- TEST-004: validateFullURL branches ---

func TestValidateFullURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid https", "https://example.com/api/v1/x", true},
		{"valid http", "http://example.com/api", true},
		{"parse error (control byte)", "http://example.com/\x00bad", false},
		{"empty host", "http:///api/v1/x", false},
		{"non-http scheme", "ftp://example.com/api", false},
		{"javascript scheme", "javascript://api/v1", false},
		{"userinfo basic auth", "http://user:pass@example.com/api/v1/x", false},
		{"userinfo no password", "http://user@example.com/api/v1/x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := validateFullURL(tc.in)
			assert.Equal(t, tc.ok, ok, "validateFullURL(%q) ok=%v, want %v", tc.in, ok, tc.ok)
		})
	}
}

// --- TEST-005: reconstructTemplateLiteral branches ---

func TestReconstructTemplateLiteral(t *testing.T) {
	cases := []struct {
		name    string
		segment string
		want    string
		ok      bool
	}{
		{"simple interpolation", "/api/v1/users/${id}", "/api/v1/users/{param}", true},
		{"multiple interpolations", "/api/v2/items/${itemId}/comments/${commentId}", "/api/v2/items/{param}/comments/{param}", true},
		// Nested braces inside the interpolation must not unbalance the
		// scanner: the depth counter has to walk past the inner {} pair
		// and resume copying literals only after the outer } closes.
		{"nested object literal in interpolation", "/api/v1/q/${ {a:1} }/end", "/api/v1/q/{param}/end", true},
		{"nested function call", "/api/v1/x/${fn({k:v})}/y", "/api/v1/x/{param}/y", true},
		{"no api indicator", "/no/indicator/here", "", false},
		{"contains whitespace", "/api/v1/x with space", "", false},
		{"trim before first slash", "prefix/api/v1/x", "/api/v1/x", true},
		{"empty segment", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := reconstructTemplateLiteral([]byte(tc.segment))
			assert.Equal(t, tc.ok, ok, "reconstructTemplateLiteral(%q) ok=%v want %v", tc.segment, ok, tc.ok)
			if ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// --- TEST-006: MaxTotalTime deadline behavior ---

func TestReplayJSExtracted_MaxTotalTimeDeadline(t *testing.T) {
	// The probe handler always sleeps for `handlerSleep`. Without the
	// MaxTotalTime cap, hitting all `pathCount` paths sequentially would
	// take ~handlerSleep * pathCount. The MaxTotalTime is set well below
	// that, so the loop must exit early.
	//
	// We assert two things: (a) the elapsed wall-clock is bounded by the
	// deadline plus a generous slack (so the test is not flaky on slow
	// CI runners or under -race), and (b) strictly fewer than pathCount
	// probes hit the server.
	const (
		pathCount    = 8
		handlerSleep = 250 * time.Millisecond
		perRequest   = 350 * time.Millisecond
		totalBudget  = 600 * time.Millisecond
		slack        = 3 * time.Second // generous: race detector + CI variance
	)

	hits := int32(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(handlerSleep)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	// Build pathCount distinct API paths.
	var jsBody []byte
	for i := 0; i < pathCount; i++ {
		jsBody = append(jsBody, []byte(`"/api/v1/p`+string(rune('a'+i))+`" `)...)
	}

	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      srv.URL + "/app.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: jsBody},
		},
	}

	cfg := allowLocal(srv)
	cfg.Timeout = perRequest
	cfg.MaxTotalTime = totalBudget
	cfg.MaxEndpoints = pathCount * 2 // ensure MaxEndpoints isn't what stops us

	start := time.Now()
	ReplayJSExtracted(context.Background(), requests, cfg)
	elapsed := time.Since(start)

	upperBound := totalBudget + slack
	assert.Less(t, elapsed, upperBound,
		"MaxTotalTime must bound wall-clock time (got %v, ceiling %v)", elapsed, upperBound)
	finalHits := atomic.LoadInt32(&hits)
	assert.Less(t, finalHits, int32(pathCount),
		"deadline must terminate the probe loop before all %d paths run (got %d)", pathCount, finalHits)
}

// --- TEST-007: flattenHeaders ---

func TestFlattenHeaders(t *testing.T) {
	t.Run("single value", func(t *testing.T) {
		h := http.Header{"Content-Type": []string{"application/json"}}
		got := flattenHeaders(h)
		assert.Equal(t, "application/json", got["Content-Type"])
	})
	t.Run("multi-value keeps first", func(t *testing.T) {
		h := http.Header{"Set-Cookie": []string{"a=1", "b=2"}}
		got := flattenHeaders(h)
		assert.Equal(t, "a=1", got["Set-Cookie"], "documented contract: only first value is preserved")
	})
	t.Run("empty value slice skipped", func(t *testing.T) {
		h := http.Header{"X-Empty": []string{}}
		got := flattenHeaders(h)
		_, has := got["X-Empty"]
		assert.False(t, has, "empty []string{} must not produce a map entry")
	})
	t.Run("empty input", func(t *testing.T) {
		assert.Empty(t, flattenHeaders(http.Header{}))
	})
}

// --- TEST-008: crAPI-style multi-strategy regression ---

func TestReplayJSExtracted_CrAPIStyleRegression(t *testing.T) {
	// Curated fixture exercising the four extraction strategies that
	// together produced the headline "29 endpoints on OWASP crAPI" result
	// (LAB-1505). A regression in any one strategy will drop entries from
	// the expected set.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Anything matching a known crAPI endpoint returns 200/JSON; the
		// rest 404 (will be filtered by the same-origin/404 logic).
		known := map[string]bool{
			"/identity/api/auth/login":                  true,
			"/identity/api/v2/user/dashboard":           true,
			"/workshop/api/shop/products":               true,
			"/workshop/api/merchant/contact_mechanic":   true,
			"/community/api/v2/community/posts/recent":  true,
			"/community/api/v2/coupon/validate-coupon":  true,
			"/identity/api/v2/user/change-email":        true,
			"/identity/api/v2/user/reset-password":      true,
			"/workshop/api/shop/orders":                 true,
			"/workshop/api/mechanic/receive_report":     true,
			"/identity/api/auth/v3/check-otp":           true,
			"/community/api/v2/community/posts/{param}": true,
		}
		if known[r.URL.Path] {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`)) //nolint:errcheck,gosec // test handler
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	jsBody := []byte(`
		// crAPI-style minified bundle reproducing the four extraction strategies.
		var IDENTITY = "identity/" + "api/auth/login";
		fetch("identity/" + "api/v2/user/dashboard");
		fetch("workshop/" + "api/shop/products");
		fetch("workshop/" + "api/merchant/contact_mechanic");
		var d = "community/api/v2/community/posts/recent";
		var f = "identity/api/v2/user/change-email";
		var g = "identity/api/v2/user/reset-password";
		var h = "workshop/api/shop/orders";
		var i = "workshop/api/mechanic/receive_report";
		var j = "identity/api/auth/v3/check-otp";
		const k = ` + "`/api/v2/community/posts/${postId}`" + `;
		const l = "community/api/v2/coupon/validate-coupon";
	`)

	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      srv.URL + "/static/js/main.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: jsBody},
		},
		// Discover prefixes via crawl results too.
		{URL: srv.URL + "/static/js/identity/", Source: srv.URL + "/static/js/main.js"},
		{URL: srv.URL + "/static/js/workshop/", Source: srv.URL + "/static/js/main.js"},
		{URL: srv.URL + "/static/js/community/", Source: srv.URL + "/static/js/main.js"},
	}

	cfg := allowLocal(srv)
	result := ReplayJSExtracted(context.Background(), requests, cfg)

	// Collect js-extract URLs.
	var probed []string
	for _, r := range result {
		if r.Source == "js-extract" {
			probed = append(probed, r.URL)
		}
	}

	// Lock in a subset that any of the four strategies must keep working:
	wantSubset := []string{
		srv.URL + "/identity/api/auth/login",                  // concat strategy
		srv.URL + "/identity/api/v2/user/dashboard",           // inline-prefixed quoted
		srv.URL + "/workshop/api/shop/products",               // concat strategy
		srv.URL + "/community/api/v2/community/posts/recent",  // inline-prefixed quoted
		srv.URL + "/community/api/v2/community/posts/{param}", // template literal interpolation
	}
	for _, w := range wantSubset {
		assert.Contains(t, probed, w, "fixture must produce %s — regression in extraction strategy", w)
	}

	// Headline assertion: at least 8 unique 200-returning endpoints from
	// this small fixture (the 12 'known' ones above, minus any that don't
	// match the regex strategies). 8 is conservative — current code yields
	// closer to 11. A drop below 8 indicates a real regression.
	assert.GreaterOrEqual(t, len(probed), 8,
		"expected at least 8 endpoints from crAPI-style fixture; got %d (%v)", len(probed), probed)
}

// --- CR-7: nested template literal pairing ---

func TestExtractTemplateLiteralPaths_NestedLiterals(t *testing.T) {
	// Naive sequential backtick pairing would mispair the inner backticks
	// with the outer ones, producing a garbage path. The interpolation-aware
	// walker must recurse into the inner ${`...`} and emerge with the outer
	// literal correctly bounded.
	t.Run("inner literal without API indicator is not surfaced", func(t *testing.T) {
		js := []byte("const url = `/api/v1/items/${`p${idx}`}/data`;")
		got := extractTemplateLiteralPaths(js)
		assert.Equal(t, []string{"/api/v1/items/{param}/data"}, got,
			"only the outer literal should surface; the inner `p${idx}` has no API indicator")
	})

	t.Run("nested literal must not bleed into outer reconstruction", func(t *testing.T) {
		// Failure mode of naive pairing: the inner literal's bytes leak
		// into the outer reconstruction (e.g., the closing backtick of
		// the inner pairs with the opening of the outer, producing
		// `/api/v1/outer/${`+/api/v1/inner+...`). The walker must keep
		// the outer literal exactly bounded.
		js := []byte("const u = `/api/v1/outer/${`/api/v1/inner`}/end`;")
		got := extractTemplateLiteralPaths(js)
		require.Len(t, got, 1, "exactly one outer literal expected")
		assert.Equal(t, "/api/v1/outer/{param}/end", got[0],
			"outer literal must reconstruct independently of the inner")
	})
}

func TestExtractTemplateLiteralPaths_EscapedBacktick(t *testing.T) {
	// Backslash-escaped backticks inside a template literal must not close
	// the outer literal. The walker should treat them as literal characters.
	t.Run("escaped backtick keeps outer literal intact", func(t *testing.T) {
		js := []byte("const url = `/api/v1/escaped/x\\`y/data`;")
		got := extractTemplateLiteralPaths(js)
		// Pin the exact reconstruction. The walker preserves the verbatim
		// escape bytes (`\` + backtick) — what it MUST NOT do is mispair
		// at the escaped backtick and produce `/api/v1/escaped/x` plus
		// orphaned junk. Pinning the exact string catches both directions
		// of regression: the escape being silently dropped, AND the
		// mispairing that this test was originally written to catch.
		assert.Equal(t, []string{"/api/v1/escaped/x\\`y/data"}, got,
			"escaped backtick must be preserved and the literal must remain bounded")
	})
}

// --- CR-8: 3xx redirect follow ---

func TestFetchJSBody_FollowsRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/old.js":
			http.Redirect(w, r, "/new.js", http.StatusMovedPermanently)
		case "/new.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`var endpoint = "/api/v1/redirected";`)) //nolint:errcheck,gosec // test handler
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := allowLocal(srv).withDefaults()
	body := fetchJSBody(context.Background(), cfg, srv.URL+"/old.js", srv.URL)
	require.NotNil(t, body, "fetchJSBody must follow 301 to recover the JS")
	assert.Contains(t, string(body), "/api/v1/redirected")
}

func TestFetchJSBody_RedirectLoopBounded(t *testing.T) {
	hits := int32(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		// Always redirect to itself: should bail out after maxJSRedirects.
		http.Redirect(w, r, r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()

	cfg := allowLocal(srv).withDefaults()
	body := fetchJSBody(context.Background(), cfg, srv.URL+"/loop.js", srv.URL)
	assert.Nil(t, body, "infinite redirect chain must terminate with nil body")
	// Exact equality: the original request + maxJSRedirects follow-ups =
	// maxJSRedirects+1 server hits. Off-by-one in either direction is a
	// regression in the security invariant.
	assert.Equal(t, int32(maxJSRedirects+1), atomic.LoadInt32(&hits),
		"redirect-loop bound must produce exactly maxJSRedirects+1 hits")
}

func TestFetchJSBody_RedirectToCrossOriginRejected(t *testing.T) {
	// A redirect that lands on a different origin must be rejected by the
	// same-origin gate (unless AllowCrossOrigin is set), even when the
	// initial request was same-origin. We attribute the rejection by
	// asserting zero hits on the off-origin server.
	offHits := int32(0)
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&offHits, 1)
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`var leak = "/api/v1/leak";`)) //nolint:errcheck,gosec // test handler
	}))
	defer off.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, off.URL+"/cdn.js", http.StatusFound)
	}))
	defer srv.Close()

	cfg := allowLocal(srv).withDefaults()
	body := fetchJSBody(context.Background(), cfg, srv.URL+"/redir.js", srv.URL)
	assert.Nil(t, body, "redirect to cross-origin host must be rejected when AllowCrossOrigin is false")
	assert.Equal(t, int32(0), atomic.LoadInt32(&offHits),
		"the off-origin server must not be hit — rejection must happen at the same-origin gate")
}

// --- TEST-004 (iter-5): resolveRedirect direct cases ---

func TestResolveRedirect(t *testing.T) {
	cases := []struct {
		name    string
		current string
		loc     string
		want    string
		wantErr bool
	}{
		{"absolute https", "https://example.com/old", "https://other.example/new", "https://other.example/new", false},
		{"path-relative", "https://example.com/dir/old.js", "/abs/new.js", "https://example.com/abs/new.js", false},
		{"parent-relative", "https://example.com/dir/sub/old.js", "../new.js", "https://example.com/dir/new.js", false},
		{"scheme-relative", "https://example.com/old", "//cdn.example/new.js", "https://cdn.example/new.js", false},
		{"same-page anchor", "https://example.com/old", "#frag", "https://example.com/old#frag", false},
		// url.Parse("") returns the zero-value URL; ResolveReference
		// against the current URL returns the current URL unchanged.
		// fetchJSBody's caller-side code rejects an empty Location BEFORE
		// invoking resolveRedirect, so this case documents the resolver's
		// raw contract rather than a code path reached at runtime.
		{"empty location returns current URL unchanged", "https://example.com/old", "", "https://example.com/old", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveRedirect(tc.current, tc.loc)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestResolveRedirect_InvalidCurrent(t *testing.T) {
	// Control byte forces url.Parse to error.
	_, err := resolveRedirect("http://example.com/\x00bad", "/new")
	assert.Error(t, err)
}

// --- TEST-001 (iter-5): caller's *http.Client is not mutated by withDefaults ---

func TestJSReplayConfig_WithDefaults_DoesNotMutateCallerClient(t *testing.T) {
	// Hand withDefaults a client whose CheckRedirect IS NOT noRedirect.
	// withDefaults must shallow-copy the client and set CheckRedirect on
	// the copy — the caller's original CheckRedirect must remain unchanged.
	called := int32(0)
	originalCheck := func(*http.Request, []*http.Request) error {
		atomic.AddInt32(&called, 1)
		return nil
	}
	caller := &http.Client{
		CheckRedirect: originalCheck,
		Transport:     &http.Transport{},
	}

	for _, allowPrivate := range []bool{false, true} {
		t.Run("AllowPrivate="+map[bool]string{false: "false", true: "true"}[allowPrivate], func(t *testing.T) {
			cfg := JSReplayConfig{Client: caller, AllowPrivate: allowPrivate}.withDefaults()
			// Sanity: withDefaults installed noRedirect on the copy.
			err := cfg.Client.CheckRedirect(nil, nil)
			assert.True(t, errors.Is(err, http.ErrUseLastResponse),
				"withDefaults must install noRedirect on the returned client")
			// Caller's CheckRedirect must still be the original.
			require.NotNil(t, caller.CheckRedirect, "caller.CheckRedirect must not be wiped")
			_ = caller.CheckRedirect(nil, nil)
		})
	}
	assert.Equal(t, int32(2), atomic.LoadInt32(&called),
		"caller.CheckRedirect must be preserved across both AllowPrivate modes")
}
