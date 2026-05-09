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

package jsstatic

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// makeSourcemapDataURI encodes a sourcesContent map as a data URI.
func makeSourcemapDataURI(sourcesContent []string) string {
	doc := map[string]interface{}{
		"version":        3,
		"sources":        []string{"app.ts"},
		"sourcesContent": sourcesContent,
	}
	b, _ := json.Marshal(doc)
	encoded := base64.StdEncoding.EncodeToString(b)
	return "data:application/json;base64," + encoded
}

func TestSourcemap_NoComment(t *testing.T) {
	bundle := []byte(`console.log("hello world");`)
	sources, stats := recoverSourcemap(bundle, "", Options{})
	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d: %v", len(sources), sources)
	}
	if stats.SourcemapFetchFails != 0 {
		t.Errorf("expected 0 fetch fails, got %d", stats.SourcemapFetchFails)
	}
}

func TestSourcemap_DataURIInline(t *testing.T) {
	content := []string{"export function hello() { return 'hello'; }"}
	uri := makeSourcemapDataURI(content)
	bundle := []byte("console.log(1);\n//# sourceMappingURL=" + uri + "\n")

	sources, stats := recoverSourcemap(bundle, "", Options{})
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d: %v", len(sources), sources)
	}
	if sources[0] != content[0] {
		t.Errorf("source content mismatch: got %q, want %q", sources[0], content[0])
	}
	if stats.SourcemapFetchFails != 0 {
		t.Errorf("expected 0 fetch fails, got %d", stats.SourcemapFetchFails)
	}
	if stats.SourcemapsRecovered != 1 {
		t.Errorf("expected 1 sourcemap recovered, got %d", stats.SourcemapsRecovered)
	}
}

func TestSourcemap_DataURIInline_NonJSON(t *testing.T) {
	// Bad base64 / non-JSON payload -> fail counted, no sources.
	bundle := []byte("console.log(1);\n//# sourceMappingURL=data:application/json;base64,!!!not_base64!!!\n")

	sources, stats := recoverSourcemap(bundle, "", Options{})
	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(sources))
	}
	if stats.SourcemapFetchFails != 1 {
		t.Errorf("expected 1 fetch fail, got %d", stats.SourcemapFetchFails)
	}
}

func TestSourcemap_CommentSyntaxVariants(t *testing.T) {
	content := []string{"var x = 1;"}
	uri := makeSourcemapDataURI(content)

	// Both //# and //@ forms should be detected.
	for _, prefix := range []string{"//# ", "//@ "} {
		bundle := []byte("console.log(1);\n" + prefix + "sourceMappingURL=" + uri + "\n")
		sources, stats := recoverSourcemap(bundle, "", Options{})
		if len(sources) != 1 {
			t.Errorf("prefix %q: expected 1 source, got %d", prefix, len(sources))
		}
		if stats.SourcemapsRecovered != 1 {
			t.Errorf("prefix %q: expected 1 recovered, got %d", prefix, stats.SourcemapsRecovered)
		}
	}
}

func TestSourcemap_CommentNotInTrailingWindow(t *testing.T) {
	content := []string{"var x = 1;"}
	uri := makeSourcemapDataURI(content)
	// Place the comment at the very beginning, then pad with >2KB of filler.
	comment := "//# sourceMappingURL=" + uri + "\n"
	filler := strings.Repeat("x", 3000)
	bundle := []byte(comment + filler)

	sources, stats := recoverSourcemap(bundle, "", Options{})
	if len(sources) != 0 {
		t.Errorf("expected 0 sources (comment outside trailing window), got %d", len(sources))
	}
	if stats.SourcemapFetchFails != 0 {
		t.Errorf("expected 0 fetch fails, got %d", stats.SourcemapFetchFails)
	}
}

// ---- Task 7: remote sourcemap fetch tests ----

// makeSourcemapJSON returns a valid sourcemap JSON body with the given sourcesContent.
func makeSourcemapJSON(sourcesContent []string) []byte {
	doc := map[string]interface{}{
		"version":        3,
		"sources":        []string{"app.ts"},
		"sourcesContent": sourcesContent,
	}
	b, _ := json.Marshal(doc)
	return b
}

func TestSourcemap_RemoteSourcesContent(t *testing.T) {
	content := []string{"export const x = 1;"}
	body := makeSourcemapJSON(content)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	mapURL := srv.URL + "/app.js.map"
	bundleURL := srv.URL + "/app.js"
	bundle := []byte(fmt.Sprintf("console.log(1);\n//# sourceMappingURL=%s\n", mapURL))

	opts := Options{
		FetchSourcemaps: true,
		AllowPrivate:    true, // test server is on 127.0.0.1
		HTTPClient:      srv.Client(),
	}
	sources, stats := recoverSourcemap(bundle, bundleURL, opts)
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d: %v", len(sources), sources)
	}
	if sources[0] != content[0] {
		t.Errorf("source mismatch: got %q, want %q", sources[0], content[0])
	}
	if stats.SourcemapsRecovered != 1 {
		t.Errorf("expected 1 recovered, got %d", stats.SourcemapsRecovered)
	}
}

func TestSourcemap_RemoteFetch404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	mapURL := srv.URL + "/app.js.map"
	bundleURL := srv.URL + "/app.js"
	bundle := []byte(fmt.Sprintf("console.log(1);\n//# sourceMappingURL=%s\n", mapURL))

	opts := Options{
		FetchSourcemaps: true,
		AllowPrivate:    true,
		HTTPClient:      srv.Client(),
	}
	sources, stats := recoverSourcemap(bundle, bundleURL, opts)
	if len(sources) != 0 {
		t.Errorf("expected 0 sources on 404, got %d", len(sources))
	}
	if stats.SourcemapFetchFails != 1 {
		t.Errorf("expected 1 fetch fail on 404, got %d", stats.SourcemapFetchFails)
	}
}

func TestSourcemap_RemoteFetchTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang forever to trigger client timeout.
		<-r.Context().Done()
	}))
	defer srv.Close()

	mapURL := srv.URL + "/app.js.map"
	bundleURL := srv.URL + "/app.js"
	bundle := []byte(fmt.Sprintf("console.log(1);\n//# sourceMappingURL=%s\n", mapURL))

	client := &http.Client{Timeout: 50 * time.Millisecond}
	opts := Options{
		FetchSourcemaps: true,
		AllowPrivate:    true,
		HTTPClient:      client,
	}
	sources, stats := recoverSourcemap(bundle, bundleURL, opts)
	if len(sources) != 0 {
		t.Errorf("expected 0 sources on timeout, got %d", len(sources))
	}
	if stats.SourcemapFetchFails != 1 {
		t.Errorf("expected 1 fetch fail on timeout, got %d", stats.SourcemapFetchFails)
	}
}

func TestSourcemap_FetchSourcemapsDisabled(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mapURL := srv.URL + "/app.js.map"
	bundleURL := srv.URL + "/app.js"
	bundle := []byte(fmt.Sprintf("console.log(1);\n//# sourceMappingURL=%s\n", mapURL))

	opts := Options{
		FetchSourcemaps: false,
		HTTPClient:      srv.Client(),
	}
	sources, _ := recoverSourcemap(bundle, bundleURL, opts)
	if len(sources) != 0 {
		t.Errorf("expected 0 sources when FetchSourcemaps=false, got %d", len(sources))
	}
	if hits.Load() != 0 {
		t.Errorf("server should not have been hit when FetchSourcemaps=false, got %d hits", hits.Load())
	}
}

func TestSourcemap_CrossHostRefused(t *testing.T) {
	// Bundle on host-a, sourcemap URL on host-b -> should not fetch.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		content := makeSourcemapJSON([]string{"var x = 1;"})
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	// Bundle URL has a different host than the sourcemap URL.
	mapURL := srv.URL + "/app.js.map"
	// Use a completely different host for the bundle origin.
	bundleURL := "https://different-host.example.com/bundle.js"
	bundle := []byte(fmt.Sprintf("console.log(1);\n//# sourceMappingURL=%s\n", mapURL))

	opts := Options{
		FetchSourcemaps: true,
		AllowPrivate:    true,
		HTTPClient:      srv.Client(),
	}
	sources, _ := recoverSourcemap(bundle, bundleURL, opts)
	if len(sources) != 0 {
		t.Errorf("expected 0 sources for cross-host sourcemap, got %d", len(sources))
	}
	if hits.Load() != 0 {
		t.Errorf("server should not have been hit for cross-host sourcemap, got %d hits", hits.Load())
	}
}

func TestSourcemap_AllowPrivateGate(t *testing.T) {
	content := []string{"var y = 2;"}
	body := makeSourcemapJSON(content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	mapURL := srv.URL + "/app.js.map"
	bundleURL := srv.URL + "/app.js"
	bundle := []byte(fmt.Sprintf("console.log(1);\n//# sourceMappingURL=%s\n", mapURL))

	// AllowPrivate=false -> SSRF protection blocks loopback fetch -> fail counted.
	optsBlocked := Options{
		FetchSourcemaps: true,
		AllowPrivate:    false,
		// HTTPClient is nil so defaultSourcemapClient is used (SSRF protected).
	}
	sourcesBlocked, statsBlocked := recoverSourcemap(bundle, bundleURL, optsBlocked)
	if len(sourcesBlocked) != 0 {
		t.Errorf("AllowPrivate=false: expected 0 sources, got %d", len(sourcesBlocked))
	}
	if statsBlocked.SourcemapFetchFails != 1 {
		t.Errorf("AllowPrivate=false: expected 1 fail, got %d", statsBlocked.SourcemapFetchFails)
	}

	// AllowPrivate=true -> fetch succeeds.
	optsAllowed := Options{
		FetchSourcemaps: true,
		AllowPrivate:    true,
		HTTPClient:      srv.Client(),
	}
	sourcesAllowed, statsAllowed := recoverSourcemap(bundle, bundleURL, optsAllowed)
	if len(sourcesAllowed) != 1 {
		t.Fatalf("AllowPrivate=true: expected 1 source, got %d", len(sourcesAllowed))
	}
	if statsAllowed.SourcemapsRecovered != 1 {
		t.Errorf("AllowPrivate=true: expected 1 recovered, got %d", statsAllowed.SourcemapsRecovered)
	}
}

func TestSourcemap_OversizedResponseRejected(t *testing.T) {
	// Server streams >10MB; should abort and count as a fail.
	oversizeLimit := 10 * 1024 * 1024
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write more than the limit.
		chunk := strings.Repeat("x", 1024)
		for i := 0; i <= oversizeLimit/len(chunk)+1; i++ {
			_, err := fmt.Fprint(w, chunk)
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	mapURL := srv.URL + "/app.js.map"
	bundleURL := srv.URL + "/app.js"
	bundle := []byte(fmt.Sprintf("console.log(1);\n//# sourceMappingURL=%s\n", mapURL))

	opts := Options{
		FetchSourcemaps: true,
		AllowPrivate:    true,
		HTTPClient:      srv.Client(),
	}
	sources, stats := recoverSourcemap(bundle, bundleURL, opts)
	if len(sources) != 0 {
		t.Errorf("expected 0 sources for oversized response, got %d", len(sources))
	}
	if stats.SourcemapFetchFails != 1 {
		t.Errorf("expected 1 fail for oversized response, got %d", stats.SourcemapFetchFails)
	}
}
