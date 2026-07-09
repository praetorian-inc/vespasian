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

// TEST-001 regression: SetCookies on a BrowserManager whose browser field
// is nil must return a clear "browser not connected" error. The error
// string is load-bearing — crawlHeadless wraps it via `inject cookies: %w`
// and operators may match on it when triaging a failed crawl. The default
// NewBrowserManager path always sets browser, so this guard only fires
// when a caller (test or future refactor) constructs BrowserManager
// directly.
func TestBrowserManager_SetCookies_NilBrowserReturnsError(t *testing.T) {
	bm := &BrowserManager{}
	err := bm.SetCookies(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not connected") {
		t.Errorf("error message %q should contain 'not connected'", err.Error())
	}
}

// Additional guard: calling SetCookies on a nil *BrowserManager must also
// return the same "browser not connected" error rather than panicking
// with a nil-pointer dereference. Matches the CodeRabbit guidance on
// PR #68 review 4156714509.
func TestBrowserManager_SetCookies_NilReceiverReturnsError(t *testing.T) {
	var bm *BrowserManager
	err := bm.SetCookies(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not connected") {
		t.Errorf("error message %q should contain 'not connected'", err.Error())
	}
}

func TestConfigureLauncher(t *testing.T) {
	t.Run("sandbox", func(t *testing.T) {
		tests := []struct {
			name      string
			noSandbox bool
			envVal    string
			wantFlag  bool
		}{
			{"explicit NoSandbox", true, "", true},
			{"explicit NoSandbox with env", true, "true", true},
			{"no flags no env", false, "", false},
			{"env true enables NoSandbox", false, "true", true},
			{"env false does not enable NoSandbox", false, "false", false},
			{"env arbitrary value does not enable NoSandbox", false, "1", false},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Setenv("VESPASIAN_NO_SANDBOX", tt.envVal)
				l, err := configureLauncher(BrowserOptions{NoSandbox: tt.noSandbox})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				got := l.Has("no-sandbox")
				if got != tt.wantFlag {
					t.Errorf("Has(no-sandbox) = %v, want %v", got, tt.wantFlag)
				}
			})
		}
	})

	t.Run("proxy", func(t *testing.T) {
		t.Run("valid proxy sets flag", func(t *testing.T) {
			l, err := configureLauncher(BrowserOptions{Proxy: "http://127.0.0.1:8080"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !l.Has("proxy-server") {
				t.Error("expected proxy-server flag to be set")
			}
		})
		t.Run("invalid proxy returns error", func(t *testing.T) {
			_, err := configureLauncher(BrowserOptions{Proxy: "not a valid proxy"})
			if err == nil {
				t.Fatal("expected error for invalid proxy, got nil")
			}
		})
	})

	t.Run("chrome path", func(t *testing.T) {
		l, err := configureLauncher(BrowserOptions{ChromePath: "/usr/bin/chromium"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !l.Has("rod-bin") {
			t.Error("expected rod-bin flag to be set after ChromePath")
		}
	})
}
