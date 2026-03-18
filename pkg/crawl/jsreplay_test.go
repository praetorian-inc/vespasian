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
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
				"/api/v2/users",
				"/v1/items",
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
				// Both /api/v2/public/health and /v1/metrics have no inline prefix,
				// so they get combined with discovered prefix "identity/".
				"/identity/api/auth/login",
				"/identity/api/v2/public/health",
				"/identity/v1/metrics",
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
	// Simulates crAPI: JS has paths like "api/auth/login" and crawl results
	// reveal service prefixes "identity/", "workshop/", etc.
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

func TestReplayJSExtracted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/v2/user/dashboard":
			if r.Header.Get("Authorization") != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name":"Test User"}`)) //nolint:errcheck
		case "/workshop/api/shop/products":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"id":1}]`)) //nolint:errcheck
		default:
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html>SPA</html>")) //nolint:errcheck
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

	cfg := JSReplayConfig{
		Headers: map[string]string{"Authorization": "Bearer test-token"},
		Client:  srv.Client(),
	}

	result := ReplayJSExtracted(context.Background(), requests, cfg)

	// Original requests preserved.
	require.GreaterOrEqual(t, len(result), 2)

	// Collect appended URLs.
	appended := make(map[string]ObservedRequest)
	for _, req := range result[2:] {
		appended[req.URL] = req
	}

	// Correctly prefixed endpoint should return JSON.
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
		w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
	}))
	defer srv.Close()

	// JS contains a full URL pointing to our test server.
	jsBody := []byte(`const url = "` + srv.URL + `/api/v1/health";`)

	requests := []ObservedRequest{
		{
			Method: "GET",
			URL:    "http://other-host:3000/app.js",
			Source: "katana",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        jsBody,
			},
		},
	}

	cfg := JSReplayConfig{Client: srv.Client()}
	result := ReplayJSExtracted(context.Background(), requests, cfg)

	require.Len(t, result, 2)
	assert.Equal(t, srv.URL+"/api/v1/health", result[1].URL)
	assert.Equal(t, "application/json", result[1].Response.ContentType)
}

func TestReplayJSExtracted_NoJSFiles(t *testing.T) {
	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      "https://example.com/",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "text/html"},
		},
	}
	result := ReplayJSExtracted(context.Background(), requests, JSReplayConfig{})
	assert.Len(t, result, 1)
}

func TestReplayJSExtracted_MaxEndpoints(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck
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

	cfg := JSReplayConfig{Client: srv.Client(), MaxEndpoints: 2}
	result := ReplayJSExtracted(context.Background(), requests, cfg)

	assert.LessOrEqual(t, len(result), 3) // 1 original + max 2 probed
	assert.LessOrEqual(t, callCount, 2)
}

func TestReplayJSExtracted_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`)) //nolint:errcheck
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	requests := []ObservedRequest{
		{
			Method:   "GET",
			URL:      srv.URL + "/app.js",
			Source:   "katana",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript", Body: []byte(`"/api/v2/data"`)},
		},
	}

	result := ReplayJSExtracted(ctx, requests, JSReplayConfig{Client: srv.Client()})
	assert.Len(t, result, 1)
}

func TestReplayJSExtracted_TruncatedBody(t *testing.T) {
	// Simulate a JS file whose body was truncated at MaxResponseBodySize.
	// The API paths are only in the "full" version served by the server.
	fullJS := make([]byte, MaxResponseBodySize+100)
	copy(fullJS, []byte(`/* padding */`))
	// Place API path near the end (past truncation point).
	copy(fullJS[MaxResponseBodySize+10:], []byte(`"/api/v2/hidden"`))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(fullJS) //nolint:errcheck
		case "/api/v2/hidden":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"found":true}`)) //nolint:errcheck
		}
	}))
	defer srv.Close()

	// Crawl result has truncated body (exactly MaxResponseBodySize).
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

	cfg := JSReplayConfig{Client: srv.Client()}
	result := ReplayJSExtracted(context.Background(), requests, cfg)

	require.Len(t, result, 2)
	assert.Equal(t, srv.URL+"/api/v2/hidden", result[1].URL)
	assert.Equal(t, "application/json", result[1].Response.ContentType)
}
