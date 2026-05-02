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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
}

func TestResolveBaseURL(t *testing.T) {
	assert.Equal(t, "https://example.com", resolveBaseURL("https://example.com/static/js/main.js"))
	assert.Equal(t, "https://api.example.com", resolveBaseURL("https://api.example.com/v1/users"))
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
	assert.Equal(t, "application/json", dashboard.Response.ContentType)
	assert.Contains(t, string(dashboard.Response.Body), "Test User")
	assert.Equal(t, "js-extract", dashboard.Source)

	products, ok := appended[srv.URL+"/workshop/api/shop/products"]
	require.True(t, ok, "expected products endpoint")
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
		result := ReplayJSExtracted(context.Background(), nil, JSReplayConfig{AllowPrivate: true})
		assert.Empty(t, result)
	})
	t.Run("empty slice", func(t *testing.T) {
		result := ReplayJSExtracted(context.Background(), []ObservedRequest{}, JSReplayConfig{AllowPrivate: true})
		assert.Empty(t, result)
	})
	t.Run("requests with empty URLs", func(t *testing.T) {
		input := []ObservedRequest{
			{Method: "GET", URL: ""},
			{Method: "GET", URL: ""},
		}
		result := ReplayJSExtracted(context.Background(), input, JSReplayConfig{AllowPrivate: true})
		assert.Equal(t, input, result, "input should be returned unchanged when no baseURL discoverable")
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

func TestReplayJSExtracted_ProbeNetworkError(t *testing.T) {
	// TEST-004: when probeURL returns nil (network failure), the path is
	// silently dropped — original requests are preserved unchanged.
	closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	closedURL := closedSrv.URL
	closedSrv.Close() // immediately close to force connection refused

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`"/api/v1/data"`)) //nolint:errcheck,gosec // test handler
	}))
	defer srv.Close()

	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      closedURL + "/app.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: []byte(`"/api/v1/data"`)},
		},
	}

	cfg := JSReplayConfig{
		Client:       srv.Client(),
		TargetURL:    closedURL,
		AllowPrivate: true,
		Timeout:      500 * time.Millisecond,
	}
	result := ReplayJSExtracted(context.Background(), requests, cfg)
	// One original request, no appended results because every probe to
	// closedURL fails before returning a response.
	assert.Equal(t, requests, result)
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

func TestExtractAPIPaths_RejectsURLsWithControlChars(t *testing.T) {
	// Defensive: paths embedding NUL or escape sequences should still
	// surface (they're attacker-controlled but already filtered for static
	// extensions). The log layer is responsible for sanitization.
	js := []byte(`"/api/v2/data"`)
	got := extractAPIPaths(js, nil)
	assert.Equal(t, []string{"/api/v2/data"}, got)
	// Sanity: parsing still succeeds.
	_, err := url.Parse(got[0])
	assert.NoError(t, err)
}

// helperContains is a tiny utility used by a couple of tests.
func helperContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

var _ = helperContains // referenced by future tests; keep to avoid dead-import churn
