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
	"strings"
	"testing"
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
			name:        "cookie without value",
			targetURL:   "https://example.com",
			cookieValue: "flag",
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
	if p.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", p.Domain, "example.com")
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
	if params[0].Domain != "localhost" {
		t.Errorf("Domain = %q, want %q", params[0].Domain, "localhost")
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
