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

	"github.com/go-rod/rod/lib/launcher/flags"
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
			if got := l.Get("proxy-server"); got != "http://127.0.0.1:8080" {
				t.Errorf("Get(proxy-server) = %q, want http://127.0.0.1:8080", got)
			}
		})
		t.Run("invalid proxy returns error", func(t *testing.T) {
			_, err := configureLauncher(BrowserOptions{Proxy: "not a valid proxy"})
			if err == nil {
				t.Fatal("expected error for invalid proxy, got nil")
			}
			if !strings.Contains(err.Error(), "proxy") {
				t.Errorf("error %q should mention proxy", err.Error())
			}
		})
	})

	t.Run("chrome path", func(t *testing.T) {
		// Explicit ChromePath wins and LookPath is never consulted, even when
		// LookPath would resolve a different binary.
		stubLookPath(t, "/should/not/be/used", true)
		l, err := configureLauncher(BrowserOptions{ChromePath: "/usr/bin/chromium"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := l.Get("rod-bin"); got != "/usr/bin/chromium" {
			t.Errorf("Get(rod-bin) = %q, want /usr/bin/chromium", got)
		}
	})

	// Finding 1 (LAB-4999): when ChromePath is unset the launcher pins the
	// system browser via LookPath and never falls through to go-rod's
	// third-party-mirror download unless downloads are explicitly opted in.
	t.Run("browser binary pinning", func(t *testing.T) {
		t.Run("LookPath found pins that binary", func(t *testing.T) {
			stubLookPath(t, "/opt/google/chrome/chrome", true)
			l, err := configureLauncher(BrowserOptions{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := l.Get("rod-bin"); got != "/opt/google/chrome/chrome" {
				t.Errorf("Get(rod-bin) = %q, want /opt/google/chrome/chrome", got)
			}
		})

		t.Run("no browser and no opt-in errors without pinning", func(t *testing.T) {
			t.Setenv("VESPASIAN_ALLOW_BROWSER_DOWNLOAD", "")
			stubLookPath(t, "", false)
			l, err := configureLauncher(BrowserOptions{})
			if err == nil {
				t.Fatal("expected error when no system browser is found, got nil")
			}
			if !strings.Contains(err.Error(), "VESPASIAN_ALLOW_BROWSER_DOWNLOAD") {
				t.Errorf("error %q should name the opt-in env var", err.Error())
			}
			if l != nil {
				t.Error("expected nil launcher on error")
			}
		})

		t.Run("no browser with field opt-in allows download", func(t *testing.T) {
			t.Setenv("VESPASIAN_ALLOW_BROWSER_DOWNLOAD", "")
			stubLookPath(t, "", false)
			l, err := configureLauncher(BrowserOptions{AllowBrowserDownload: true})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Binary left unset so go-rod performs its managed download.
			if got := l.Get("rod-bin"); got != "" {
				t.Errorf("Get(rod-bin) = %q, want empty (download fallback)", got)
			}
		})

		t.Run("no browser with env opt-in allows download", func(t *testing.T) {
			t.Setenv("VESPASIAN_ALLOW_BROWSER_DOWNLOAD", "true")
			stubLookPath(t, "", false)
			l, err := configureLauncher(BrowserOptions{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := l.Get("rod-bin"); got != "" {
				t.Errorf("Get(rod-bin) = %q, want empty (download fallback)", got)
			}
		})
	})

	// Finding 2 (LAB-4999): telemetry/phone-home-disabling flags are always
	// applied, and disable-features is appended to (preserving go-rod's own
	// site-per-process / TranslateUI defaults) rather than overwritten.
	t.Run("telemetry flags", func(t *testing.T) {
		stubLookPath(t, "/usr/bin/chromium", true)
		l, err := configureLauncher(BrowserOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, flag := range []flags.Flag{"disable-component-update", "disable-domain-reliability", "no-pings"} {
			if !l.Has(flag) {
				t.Errorf("expected launcher to have flag %q", flag)
			}
		}
		feats, ok := l.GetFlags("disable-features")
		if !ok {
			t.Fatal("expected disable-features flag to be set")
		}
		for _, want := range []string{"site-per-process", "TranslateUI", "OptimizationHints", "AutofillServerCommunication"} {
			if !containsStr(feats, want) {
				t.Errorf("disable-features %v should contain %q", feats, want)
			}
		}
	})
}

// stubLookPath swaps the package-level browserLookPath for the duration of a
// test so the no-browser-found and found paths can be exercised regardless of
// what is installed on the host. The original is restored via t.Cleanup.
func stubLookPath(t *testing.T, path string, found bool) {
	t.Helper()
	orig := browserLookPath
	browserLookPath = func() (string, bool) { return path, found }
	t.Cleanup(func() { browserLookPath = orig })
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestNewBrowserManager_InvalidProxyReturnsError(t *testing.T) {
	mgr, err := NewBrowserManager(BrowserOptions{Proxy: "not a valid proxy"})
	if err == nil {
		t.Fatal("expected error for invalid proxy, got nil")
	}
	if mgr != nil {
		t.Error("expected nil manager on error")
	}
	if !strings.Contains(err.Error(), "proxy") {
		t.Errorf("error %q should mention proxy", err.Error())
	}
}
