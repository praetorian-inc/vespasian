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
	"testing"
)

func TestNeedsReplay(t *testing.T) {
	tests := []struct {
		name string
		req  ObservedRequest
		want bool
	}{
		{
			name: "empty response needs replay",
			req:  ObservedRequest{URL: "http://example.com/api/users", Method: "GET"},
			want: true,
		},
		{
			name: "response with status but no body needs replay",
			req: ObservedRequest{
				URL:      "http://example.com/api/users",
				Response: ObservedResponse{StatusCode: 200},
			},
			want: true,
		},
		{
			name: "complete response does not need replay",
			req: ObservedRequest{
				URL: "http://example.com/api/users",
				Response: ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"users":[]}`),
				},
			},
			want: false,
		},
		{
			name: "empty URL does not need replay",
			req:  ObservedRequest{URL: ""},
			want: false,
		},
		{
			name: "response with body but no status needs replay",
			req: ObservedRequest{
				URL:      "http://example.com/api/data",
				Response: ObservedResponse{Body: []byte("data")},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := needsReplay(tt.req)
			if got != tt.want {
				t.Errorf("needsReplay() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReplayRequests_NoHeaders(t *testing.T) {
	requests := []ObservedRequest{
		{URL: "http://example.com/api/test", Method: "GET"},
	}
	result := ReplayRequests(context.Background(), requests, nil)
	if len(result) != len(requests) {
		t.Fatalf("expected %d requests, got %d", len(requests), len(result))
	}
	// Should return original requests unchanged.
	if result[0].URL != requests[0].URL {
		t.Error("expected original request returned unchanged")
	}
}

func TestReplayRequests_FillsEmptyResponses(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header was injected.
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":1,"name":"test"}`)
	}))
	defer ts.Close()

	requests := []ObservedRequest{
		{
			URL:    ts.URL + "/api/users",
			Method: "GET",
			Source: "katana",
			// Empty response — simulates XHR-extracted URL.
		},
		{
			URL:    ts.URL + "/api/complete",
			Method: "GET",
			Source: "katana",
			// Already has a full response — should NOT be replayed.
			Response: ObservedResponse{
				StatusCode:  200,
				Body:        []byte(`{"existing":true}`),
				ContentType: "application/json",
			},
		},
	}

	headers := map[string]string{
		"Authorization": "Bearer test-token",
	}

	result := ReplayRequests(context.Background(), requests, headers)

	if len(result) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(result))
	}

	// First request should have been replayed.
	if result[0].Response.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result[0].Response.StatusCode)
	}
	if string(result[0].Response.Body) != `{"id":1,"name":"test"}` {
		t.Errorf("unexpected response body: %s", result[0].Response.Body)
	}
	if result[0].Response.ContentType != "application/json" {
		t.Errorf("expected content type application/json, got %s", result[0].Response.ContentType)
	}
	if result[0].Source != "katana+replay" {
		t.Errorf("expected source katana+replay, got %s", result[0].Source)
	}

	// Second request should NOT have been modified.
	if string(result[1].Response.Body) != `{"existing":true}` {
		t.Errorf("complete request should not be modified, got body: %s", result[1].Response.Body)
	}
	if result[1].Source != "katana" {
		t.Errorf("complete request source should be unchanged, got: %s", result[1].Source)
	}
}

func TestReplayRequests_DeduplicatesURLs(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer ts.Close()

	requests := []ObservedRequest{
		{URL: ts.URL + "/api/test", Method: "GET"},
		{URL: ts.URL + "/api/test", Method: "GET"}, // duplicate
		{URL: ts.URL + "/api/test", Method: "GET"}, // duplicate
	}

	headers := map[string]string{"Authorization": "Bearer tok"}
	result := ReplayRequests(context.Background(), requests, headers)

	// Only one HTTP request should have been made despite 3 duplicate URLs.
	if requestCount != 1 {
		t.Errorf("expected 1 HTTP request (deduped), got %d", requestCount)
	}

	// All 3 entries should have been updated.
	for i, r := range result {
		if r.Response.StatusCode != 200 {
			t.Errorf("request[%d] expected status 200, got %d", i, r.Response.StatusCode)
		}
	}
}

func TestReplayRequests_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	requests := []ObservedRequest{
		{URL: ts.URL + "/api/test", Method: "GET"},
	}

	headers := map[string]string{"Authorization": "Bearer tok"}
	result := ReplayRequests(ctx, requests, headers)

	// Should return without crashing. Response may or may not be filled depending on timing.
	if len(result) != 1 {
		t.Fatalf("expected 1 request, got %d", len(result))
	}
}

func TestReplayRequests_SkipsAlreadyComplete(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	requests := []ObservedRequest{
		{
			URL:    ts.URL + "/api/already-done",
			Method: "GET",
			Response: ObservedResponse{
				StatusCode: 200,
				Body:       []byte(`{"done":true}`),
			},
		},
	}

	headers := map[string]string{"Authorization": "Bearer tok"}
	ReplayRequests(context.Background(), requests, headers)

	if requestCount != 0 {
		t.Errorf("expected 0 HTTP requests for complete responses, got %d", requestCount)
	}
}

func TestReplayRequests_DoesNotMutateOriginal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"replayed":true}`)
	}))
	defer ts.Close()

	original := []ObservedRequest{
		{URL: ts.URL + "/api/test", Method: "GET", Source: "katana"},
	}

	headers := map[string]string{"Authorization": "Bearer tok"}
	result := ReplayRequests(context.Background(), original, headers)

	// Original should be unchanged.
	if original[0].Response.StatusCode != 0 {
		t.Error("original request was mutated")
	}
	if original[0].Source != "katana" {
		t.Errorf("original source was mutated to %s", original[0].Source)
	}

	// Result should have the replayed data.
	if result[0].Response.StatusCode != 200 {
		t.Errorf("replayed request should have status 200, got %d", result[0].Response.StatusCode)
	}
}

func TestExtractURLsFromBody(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		sourceURL string
		wantCount int
		wantURLs  []string
	}{
		{
			name:      "relative API URL",
			body:      `{"href":"/api/v1/users"}`,
			sourceURL: "http://example.com/api/index",
			wantCount: 1,
			wantURLs:  []string{"http://example.com/api/v1/users"},
		},
		{
			name:      "absolute same-origin API URL",
			body:      `{"link":"http://example.com/api/v2/items"}`,
			sourceURL: "http://example.com/api/index",
			wantCount: 1,
			wantURLs:  []string{"http://example.com/api/v2/items"},
		},
		{
			name:      "cross-origin URL rejected",
			body:      `{"link":"http://other.com/api/v1/data"}`,
			sourceURL: "http://example.com/api/index",
			wantCount: 0,
		},
		{
			name:      "static asset rejected",
			body:      `{"script":"/api/bundle.js"}`,
			sourceURL: "http://example.com/api/index",
			wantCount: 0,
		},
		{
			name:      "non-API relative path rejected",
			body:      `{"path":"/about"}`,
			sourceURL: "http://example.com/",
			wantCount: 0,
		},
		{
			name:      "multiple URLs extracted",
			body:      `{"users":"/api/users","items":"/api/v1/items"}`,
			sourceURL: "http://example.com/",
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls := extractURLsFromBody(tt.body, tt.sourceURL)
			if len(urls) != tt.wantCount {
				t.Errorf("extractURLsFromBody() returned %d URLs, want %d: %v", len(urls), tt.wantCount, urls)
			}
			for _, want := range tt.wantURLs {
				found := false
				for _, got := range urls {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected URL %q not found in %v", want, urls)
				}
			}
		})
	}
}

func TestLooksLikeAPIURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://example.com/api/users", true},
		{"http://example.com/v1/items", true},
		{"http://example.com/v2/items", true},
		{"http://example.com/rest/data", true},
		{"http://example.com/graphql", true},
		{"http://example.com/about", false},
		{"http://example.com/static/bundle.js", false},
		{"http://example.com/style.css", false},
		{"http://example.com/logo.png", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := looksLikeAPIURL(tt.url)
			if got != tt.want {
				t.Errorf("looksLikeAPIURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsJSONResponse(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/vnd.api+json", true},
		{"text/json", true},
		{"text/html", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ct, func(t *testing.T) {
			got := isJSONResponse(tt.ct)
			if got != tt.want {
				t.Errorf("isJSONResponse(%q) = %v, want %v", tt.ct, got, tt.want)
			}
		})
	}
}

func TestReplayAndMerge_DiscoversNewEndpoints(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/index":
			w.Header().Set("Content-Type", "application/json")
			// Response contains a link to another API endpoint.
			fmt.Fprintf(w, `{"users_url":"/api/v1/users","items_url":"/api/v1/items"}`)
		case "/api/v1/users":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[{"id":1,"name":"Alice"}]`)
		case "/api/v1/items":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[{"id":1,"title":"Widget"}]`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	requests := []ObservedRequest{
		{
			URL:    ts.URL + "/api/index",
			Method: "GET",
			Source: "katana",
			// Empty response — needs replay.
		},
	}

	headers := map[string]string{"Authorization": "Bearer test-token"}
	result := ReplayAndMerge(context.Background(), requests, headers)

	// Should have original request (replayed) + 2 discovered endpoints.
	if len(result) < 2 {
		t.Fatalf("expected at least 2 requests (original + discovered), got %d", len(result))
	}

	// Verify discovered endpoints.
	foundUsers := false
	foundItems := false
	for _, r := range result {
		if r.URL == ts.URL+"/api/v1/users" {
			foundUsers = true
			if r.Source != "replay-discovery" {
				t.Errorf("discovered endpoint should have source replay-discovery, got %s", r.Source)
			}
		}
		if r.URL == ts.URL+"/api/v1/items" {
			foundItems = true
		}
	}
	if !foundUsers {
		t.Error("expected to discover /api/v1/users endpoint")
	}
	if !foundItems {
		t.Error("expected to discover /api/v1/items endpoint")
	}
}
