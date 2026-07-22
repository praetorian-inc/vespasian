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
				// Pin a fake system browser so these cases assert sandbox flags
				// without depending on a Chrome being installed on the host
				// (e.g. arm64 dev machines); pinning is covered separately below.
				stubLookPath(t, "/usr/bin/chromium", true)
				t.Setenv("VESPASIAN_NO_SANDBOX", tt.envVal)

				// Assert Vespasian's own opt-in decision directly via the
				// self-contained helper. Unlike the launcher-baseline check
				// below, this does not observe go-rod's container default, so it
				// stays deterministic in every environment: the negative cases
				// still catch a regression that unconditionally enables the
				// sandbox flag, even in dev-containers where launcher.New() adds
				// --no-sandbox by default (LAB-4994).
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
				//
				// Load-bearing assumption: this sub-assertion only exercises the
				// configureLauncher wiring on a non-container runner, where
				// baselineNoSandbox is false (e.g. CI's ubuntu-24.04 VM). In a
				// container baselineNoSandbox is true, so want is unconditionally
				// true and this check is vacuous — the environment-independent
				// regression guard is the vespasianEnablesNoSandbox assertion
				// above. If CI ever moves to a containerized runner, restore
				// container-independent coverage of the configureLauncher wiring.
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
			stubLookPath(t, "/usr/bin/chromium", true)
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
		// Pin the proxy-validation-before-binary-pinning ordering deterministically:
		// with NO system browser resolvable, an invalid proxy must still surface as a
		// proxy error, not a "no system Chrome" error. Without stubbing LookPath this
		// guard would be host-dependent (a host with Chrome installed would let a
		// reverted pin-first ordering pass anyway). See configureLauncher's ordering note.
		t.Run("invalid proxy errors before binary pinning even with no browser", func(t *testing.T) {
			stubLookPath(t, "", false)
			_, err := configureLauncher(BrowserOptions{Proxy: "not a valid proxy"})
			if err == nil {
				t.Fatal("expected error for invalid proxy, got nil")
			}
			if !strings.Contains(err.Error(), "proxy") {
				t.Errorf("error %q should be the proxy-validation error", err.Error())
			}
			if strings.Contains(err.Error(), "system Chrome") {
				t.Errorf("proxy validation must run before binary pinning; got binary-pin error: %v", err)
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

		t.Run("no browser with arbitrary env value still errors", func(t *testing.T) {
			// Default-deny: only the exact string "true" opts in. Any other
			// non-empty value must still error rather than allow a download —
			// mirrors the NoSandbox "env false"/"env arbitrary value" cases and
			// guards against a truthy-parsing regression.
			stubLookPath(t, "", false)
			for _, v := range []string{"1", "false", "TRUE", "yes"} {
				t.Setenv("VESPASIAN_ALLOW_BROWSER_DOWNLOAD", v)
				l, err := configureLauncher(BrowserOptions{})
				if err == nil {
					t.Errorf("env %q: expected no-system-Chrome error, got nil", v)
				}
				if l != nil {
					t.Errorf("env %q: expected nil launcher on error", v)
				}
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

// TestValidateProxyAddr tests the proxy address validation.
func TestValidateProxyAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
		errMsg  string
	}{
		{"valid http", "http://127.0.0.1:8080", false, ""},
		{"valid https", "https://proxy.example.com:8443", false, ""},
		{"valid socks5", "socks5://127.0.0.1:1080", false, ""},
		{"valid http no port", "http://proxy.local", false, ""},
		{"missing scheme", "127.0.0.1:8080", true, "invalid proxy address"},
		{"ftp scheme", "ftp://proxy:21", true, "scheme must be"},
		{"empty host", "http://", true, "missing host"},
		{"embedded credentials", "http://user:pass@127.0.0.1:8080", true, "embedded credentials"},
		{"embedded user only", "http://user@127.0.0.1:8080", true, "embedded credentials"},
		{"scheme-less credentials", "user:pass@127.0.0.1:8080", true, "embedded credentials"},
		{"ipv6 with credentials", "http://user:pass@[::1]:8080", true, "embedded credentials"},
		{"ipv6 host no credentials", "http://[::1]:8080", false, ""},
		// A proxy address has no legitimate userinfo, so ANY '@' is rejected as
		// embedded credentials — including forms where the userinfo contains a
		// '/', '?' or '#' that a boundary-limited scan would miss (and that also
		// make the URL unparseable, so a parse-error echo could leak the secret).
		{"at in path rejected", "http://127.0.0.1:8080/callback@handler", true, "embedded credentials"},
		{"creds with slash in password", "http://user:pa/ss@127.0.0.1:8080", true, "embedded credentials"},
		{"creds with question in password", "http://user:pa?ss@127.0.0.1:8080", true, "embedded credentials"},
		{"creds with hash in password", "http://user:pa#ss@127.0.0.1:8080", true, "embedded credentials"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyAddr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProxyAddr(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateProxyAddr(%q) error = %q, want containing %q", tt.addr, err.Error(), tt.errMsg)
				}
			}
		})
	}

	// Verify credentials are never echoed in error messages, even when
	// other validation (e.g., scheme) would also fail.
	credentialLeakCases := []struct {
		name string
		addr string
	}{
		{"http with creds", "http://admin:s3cret@proxy:8080"},
		{"wrong scheme with creds", "ftp://admin:s3cret@proxy:21"},
		{"user only", "http://admin@proxy:8080"},
		{"scheme-less creds", "admin:s3cret@127.0.0.1:8080"},
		// Credentials must be scrubbed even when the address also fails
		// url.Parse (bad port) — the credential check runs before parsing.
		{"bad port with creds", "http://admin:s3cret@127.0.0.1:8o80"},
		// ...and when the password contains a '/' or '?' that would shift an
		// RFC-authority boundary and re-leak through the parse/scheme error.
		{"slash in password", "http://admin:s3cret/x@proxy:8080"},
		{"question in password", "http://admin:s3cret?x@proxy:8080"},
		// ...and when it contains a literal '://' (would fool a scheme-prefix
		// scan) or an extra '@'. The middle segment repeats "s3cret" so the
		// leak assertion below fails if the mask keys off the FIRST '@' (which
		// would echo "...@s3cret@...") instead of the LAST.
		{"scheme marker in password", "admin:s3cret://@proxy.local:8080"},
		{"extra at in credentials", "admin:s3cret@s3cret@proxy:8080"},
	}
	for _, tt := range credentialLeakCases {
		t.Run("redacted/"+tt.name, func(t *testing.T) {
			err := ValidateProxyAddr(tt.addr)
			if err == nil {
				t.Fatal("expected error for embedded credentials")
			}
			msg := err.Error()
			if strings.Contains(msg, "admin") || strings.Contains(msg, "s3cret") {
				t.Errorf("error message leaks credentials: %s", msg)
			}
			if !strings.Contains(msg, "xxxxx") {
				t.Errorf("error message should contain redacted placeholder 'xxxxx': %s", msg)
			}
		})
	}
}
