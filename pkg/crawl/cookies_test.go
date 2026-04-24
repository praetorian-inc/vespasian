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
	"errors"
	"strings"
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

func TestExtractCookieHeader(t *testing.T) {
	tests := []struct {
		name            string
		headers         map[string]string
		wantCookie      string
		wantRemainCount int
	}{
		{
			name:            "no cookie header",
			headers:         map[string]string{"Authorization": "Bearer token"},
			wantCookie:      "",
			wantRemainCount: 1,
		},
		{
			name:            "cookie header present",
			headers:         map[string]string{"Cookie": "JSESSIONID=abc123", "Authorization": "Bearer token"},
			wantCookie:      "JSESSIONID=abc123",
			wantRemainCount: 1,
		},
		{
			name:            "lowercase cookie header",
			headers:         map[string]string{"cookie": "JSESSIONID=abc123"},
			wantCookie:      "JSESSIONID=abc123",
			wantRemainCount: 0,
		},
		{
			name:            "mixed case cookie header",
			headers:         map[string]string{"COOKIE": "session=xyz"},
			wantCookie:      "session=xyz",
			wantRemainCount: 0,
		},
		{
			name:            "empty headers",
			headers:         map[string]string{},
			wantCookie:      "",
			wantRemainCount: 0,
		},
		{
			name:            "nil headers",
			headers:         nil,
			wantCookie:      "",
			wantRemainCount: 0,
		},
		{
			name:            "cookie with multiple values",
			headers:         map[string]string{"Cookie": "JSESSIONID=abc; token=xyz"},
			wantCookie:      "JSESSIONID=abc; token=xyz",
			wantRemainCount: 0,
		},
		{
			name: "non-cookie headers preserved",
			headers: map[string]string{
				"Cookie":        "session=abc",
				"Authorization": "Bearer token",
				"X-Custom":      "value",
			},
			wantCookie:      "session=abc",
			wantRemainCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookie, remaining := ExtractCookieHeader(tt.headers)
			if cookie != tt.wantCookie {
				t.Errorf("cookie = %q, want %q", cookie, tt.wantCookie)
			}
			if len(remaining) != tt.wantRemainCount {
				t.Errorf("remaining count = %d, want %d", len(remaining), tt.wantRemainCount)
			}
			// Verify cookie header is not in remaining
			for k := range remaining {
				if strings.EqualFold(k, "Cookie") {
					t.Errorf("remaining still contains cookie header %q", k)
				}
			}
		})
	}
}

func TestExtractCookieHeader_DoesNotMutateOriginal(t *testing.T) {
	original := map[string]string{
		"Cookie":        "session=abc",
		"Authorization": "Bearer token",
	}
	_, remaining := ExtractCookieHeader(original)

	// Original should still have Cookie
	if _, ok := original["Cookie"]; !ok {
		t.Error("original map was mutated: Cookie key removed")
	}
	// Remaining should not have Cookie
	if _, ok := remaining["Cookie"]; ok {
		t.Error("remaining contains Cookie key")
	}
}

func TestParseCookiesToParams(t *testing.T) {
	tests := []struct {
		name        string
		targetURL   string
		cookieValue string
		wantCount   int
		wantErr     bool
	}{
		{
			name:        "single cookie",
			targetURL:   "https://example.com/app",
			cookieValue: "JSESSIONID=abc123",
			wantCount:   1,
		},
		{
			name:        "multiple cookies",
			targetURL:   "https://example.com/app",
			cookieValue: "JSESSIONID=abc123; token=xyz789; pref=dark",
			wantCount:   3,
		},
		{
			name:        "cookie with equals in value",
			targetURL:   "https://example.com",
			cookieValue: "token=abc=def=ghi",
			wantCount:   1,
		},
		{
			name:        "empty cookie value",
			targetURL:   "https://example.com",
			cookieValue: "",
			wantCount:   0,
		},
		{
			name:        "whitespace-only pairs",
			targetURL:   "https://example.com",
			cookieValue: "  ;  ;  ",
			wantCount:   0,
		},
		{
			name:        "http scheme sets secure false",
			targetURL:   "http://localhost:8080/app",
			cookieValue: "JSESSIONID=abc",
			wantCount:   1,
		},
		{
			name:        "invalid target URL",
			targetURL:   "://invalid",
			cookieValue: "JSESSIONID=abc",
			wantErr:     true,
		},
		{
			name:        "bare hostname rejected",
			targetURL:   "example.com",
			cookieValue: "JSESSIONID=abc",
			wantErr:     true,
		},
		{
			name:        "scheme-only rejected",
			targetURL:   "http://",
			cookieValue: "JSESSIONID=abc",
			wantErr:     true,
		},
		{
			name:        "non-http scheme rejected",
			targetURL:   "ftp://example.com",
			cookieValue: "JSESSIONID=abc",
			wantErr:     true,
		},
		{
			name:        "cookie without value",
			targetURL:   "https://example.com",
			cookieValue: "flag",
			wantCount:   1,
		},
		// TEST-003 regression: a cookie pair whose name is empty (e.g. "=orphan")
		// is silently skipped by ParseCookiesToParams. The existing
		// "whitespace-only pairs" case covers the trimmed-empty branch, but no
		// test asserts the "valued pair with empty name" branch explicitly. A
		// refactor that changed the silent skip to an error would not be caught.
		{
			name:        "pair with empty name silently skipped",
			cookieValue: "=orphan; valid=yes",
			targetURL:   "https://example.com",
			wantCount:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParseCookiesToParams(tt.targetURL, tt.cookieValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if len(params) != tt.wantCount {
				t.Errorf("params count = %d, want %d", len(params), tt.wantCount)
			}
		})
	}
}

func TestParseCookiesToParams_CookieFields(t *testing.T) {
	params, err := ParseCookiesToParams("https://example.com:8443/app/login", "JSESSIONID=abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(params) != 1 {
		t.Fatalf("expected 1 param, got %d", len(params))
	}

	p := params[0]
	if p.Name != "JSESSIONID" {
		t.Errorf("Name = %q, want %q", p.Name, "JSESSIONID")
	}
	if p.Value != "abc123" {
		t.Errorf("Value = %q, want %q", p.Value, "abc123")
	}
	// Domain is intentionally unset: Chrome derives host-only scope from
	// URL when Domain is empty. Populating both is redundant.
	if p.Domain != "" {
		t.Errorf("Domain = %q, want %q (derived from URL)", p.Domain, "")
	}
	if p.Path != "/" {
		t.Errorf("Path = %q, want %q", p.Path, "/")
	}
	if !p.Secure {
		t.Error("Secure = false, want true for https")
	}
	if p.URL != "https://example.com:8443" {
		t.Errorf("URL = %q, want %q", p.URL, "https://example.com:8443")
	}
}

func TestParseCookiesToParams_HTTPNotSecure(t *testing.T) {
	params, err := ParseCookiesToParams("http://localhost:8080/WebGoat", "JSESSIONID=abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(params) != 1 {
		t.Fatalf("expected 1 param, got %d", len(params))
	}
	if params[0].Secure {
		t.Error("Secure = true, want false for http")
	}
	if params[0].URL != "http://localhost:8080" {
		t.Errorf("URL = %q, want %q", params[0].URL, "http://localhost:8080")
	}
}

func TestParseCookiesToParams_MultipleCookies(t *testing.T) {
	params, err := ParseCookiesToParams(
		"https://example.com",
		"JSESSIONID=abc123; csrf_token=xyz789; theme=dark",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(params) != 3 {
		t.Fatalf("expected 3 params, got %d", len(params))
	}

	// Verify each cookie name
	names := make(map[string]string)
	for _, p := range params {
		names[p.Name] = p.Value
	}
	if names["JSESSIONID"] != "abc123" {
		t.Errorf("JSESSIONID = %q, want %q", names["JSESSIONID"], "abc123")
	}
	if names["csrf_token"] != "xyz789" {
		t.Errorf("csrf_token = %q, want %q", names["csrf_token"], "xyz789")
	}
	if names["theme"] != "dark" {
		t.Errorf("theme = %q, want %q", names["theme"], "dark")
	}
}

// TEST-004/005 regression: ApplyCookieHeader is the pipeline behind the
// LAB-2222 fix. These tests pin the wiring (extract → parse → inject)
// in the default build tag so a refactor that stops calling the
// injector, or forgets to strip Cookie from engine headers, fails
// here instead of requiring the //go:build integration suite to run.

func TestApplyCookieHeader_CookiePresent_InjectsAndStripsHeader(t *testing.T) {
	var injected [][]*proto.NetworkCookieParam
	inject := func(params []*proto.NetworkCookieParam) error {
		injected = append(injected, params)
		return nil
	}
	headers := map[string]string{
		"Cookie":        "JSESSIONID=abc123",
		"Authorization": "Bearer tok",
		"X-Custom":      "v",
	}

	extra, err := ApplyCookieHeader(headers, "https://target.example/app", inject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(injected) != 1 {
		t.Fatalf("inject called %d times, want 1", len(injected))
	}
	if len(injected[0]) != 1 {
		t.Fatalf("got %d cookies, want 1", len(injected[0]))
	}
	if injected[0][0].Name != "JSESSIONID" || injected[0][0].Value != "abc123" {
		t.Errorf("got cookie %q=%q, want JSESSIONID=abc123", injected[0][0].Name, injected[0][0].Value)
	}
	if _, present := extra["Cookie"]; present {
		t.Error("Cookie header leaked into engine extra headers — would be doubly injected")
	}
	if extra["Authorization"] != "Bearer tok" {
		t.Errorf("Authorization stripped: extra=%v", extra)
	}
	if extra["X-Custom"] != "v" {
		t.Errorf("unrelated header stripped: extra=%v", extra)
	}
}

func TestApplyCookieHeader_NoCookie_InjectorNotCalled(t *testing.T) {
	called := false
	inject := func([]*proto.NetworkCookieParam) error {
		called = true
		return nil
	}
	headers := map[string]string{"Authorization": "Bearer tok"}

	extra, err := ApplyCookieHeader(headers, "https://target.example/", inject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("injector called even though no Cookie header present")
	}
	if extra["Authorization"] != "Bearer tok" {
		t.Errorf("Authorization header dropped: extra=%v", extra)
	}
}

func TestApplyCookieHeader_ParseError_Wrapped(t *testing.T) {
	inject := func([]*proto.NetworkCookieParam) error {
		t.Fatal("injector must not be called when parse fails")
		return nil
	}
	headers := map[string]string{"Cookie": "JSESSIONID=abc"}

	_, err := ApplyCookieHeader(headers, ":://invalid-url", inject)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "parse cookies:") {
		t.Errorf("want error prefix 'parse cookies:', got %q", err.Error())
	}
}

func TestApplyCookieHeader_InjectError_Wrapped(t *testing.T) {
	injectErr := errors.New("boom from CDP")
	inject := func([]*proto.NetworkCookieParam) error {
		return injectErr
	}
	headers := map[string]string{"Cookie": "JSESSIONID=abc"}

	_, err := ApplyCookieHeader(headers, "https://target.example/", inject)
	if err == nil {
		t.Fatal("expected inject error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "inject cookies:") {
		t.Errorf("want error prefix 'inject cookies:', got %q", err.Error())
	}
	if !errors.Is(err, injectErr) {
		t.Errorf("want wrapped inject error, got %v", err)
	}
}

func TestApplyCookieHeader_CaseInsensitiveCookieKey(t *testing.T) {
	// Mirror TEST-002's concern on ExtractCookieHeader: lowercase "cookie"
	// must also trigger extract+inject, not leak into engine headers.
	called := false
	inject := func(params []*proto.NetworkCookieParam) error {
		called = true
		if len(params) != 1 || params[0].Name != "JSESSIONID" {
			t.Errorf("unexpected cookies passed to inject: %v", params)
		}
		return nil
	}
	headers := map[string]string{"cookie": "JSESSIONID=abc"}

	extra, err := ApplyCookieHeader(headers, "https://target.example/", inject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("lowercase cookie header did not trigger injector")
	}
	if _, present := extra["cookie"]; present {
		t.Error("lowercase cookie header leaked into engine extra headers")
	}
}

// TEST-002 regression: ExtractCookieHeader documents that concatenation of
// differently-cased Cookie keys is deterministic across runs (the
// implementation sorts keys before iterating). Without a test that mixes
// casings, removing the sort would not cause any existing test to fail
// deterministically — only flake over many runs. Pin the contract.
func TestExtractCookieHeader_DeterministicSortedConcat(t *testing.T) {
	headers := map[string]string{
		"Cookie": "a=1",
		"cookie": "b=2",
	}
	// Run the extraction many times — if the sort were removed, Go map
	// iteration randomization would surface a mismatched order within a
	// few hundred iterations.
	for i := 0; i < 200; i++ {
		got, remaining := ExtractCookieHeader(headers)
		// "Cookie" sorts before "cookie" in byte order (uppercase first).
		if got != "a=1; b=2" {
			t.Fatalf("iter %d: got %q, want %q", i, got, "a=1; b=2")
		}
		if len(remaining) != 0 {
			t.Fatalf("iter %d: remaining = %v, want empty", i, remaining)
		}
	}
}
