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

	"github.com/go-rod/rod/lib/launcher"
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
		// go-rod's launcher.New() adds --no-sandbox by default when it
		// detects a container (launcher sets defaultFlags[NoSandbox] when
		// inContainer), so l.Has("no-sandbox") reflects that default in
		// Docker/dev-containers regardless of Vespasian's own logic. Assert
		// on Vespasian's *contribution* relative to this baseline instead of
		// the absolute flag: the flag must be present whenever
		// configureLauncher opts in, and otherwise must match the launcher
		// default (Vespasian must not add it on its own). This stays
		// deterministic on CI's VM runner (no container -> baseline absent)
		// and in dev-containers (baseline present) for both uid 0 and uid != 0.
		baselineNoSandbox := launcher.New().Has("no-sandbox")

		tests := []struct {
			name        string
			noSandbox   bool
			envVal      string
			vespasianOn bool // whether configureLauncher itself enables no-sandbox
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

				// Assert Vespasian's own opt-in decision directly via the pure
				// helper. Unlike the launcher-baseline check below, this does not
				// observe go-rod's container default, so it stays deterministic in
				// every environment: the negative cases still catch a regression
				// that unconditionally enables the sandbox flag, even in
				// dev-containers where launcher.New() adds --no-sandbox by default
				// (LAB-4994).
				opts := BrowserOptions{NoSandbox: tt.noSandbox}
				if got := vespasianEnablesNoSandbox(opts); got != tt.vespasianOn {
					t.Errorf("vespasianEnablesNoSandbox = %v, want %v", got, tt.vespasianOn)
				}

				l, err := configureLauncher(opts)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				// Launcher-baseline check, retained for go-rod compatibility:
				// Vespasian forcing the flag on is authoritative; when it does
				// not, the flag should equal the launcher's baseline default.
				want := tt.vespasianOn || baselineNoSandbox
				got := l.Has("no-sandbox")
				if got != want {
					t.Errorf("Has(no-sandbox) = %v, want %v (vespasianOn=%v, baseline=%v)", got, want, tt.vespasianOn, baselineNoSandbox)
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
		l, err := configureLauncher(BrowserOptions{ChromePath: "/usr/bin/chromium"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := l.Get("rod-bin"); got != "/usr/bin/chromium" {
			t.Errorf("Get(rod-bin) = %q, want /usr/bin/chromium", got)
		}
	})
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
