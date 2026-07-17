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
	"fmt"
	"net/url"
	"os"
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// browserLookPath resolves the system browser binary. It is a package var so
// tests can exercise the no-browser-found path deterministically regardless of
// what is installed on the host (go-rod uses the same "interface for testing"
// idiom for its own exec calls). Production code always uses launcher.LookPath.
var browserLookPath = launcher.LookPath

// BrowserOptions configures Chrome launch parameters.
type BrowserOptions struct {
	Headless bool

	// NoSandbox disables Chrome's OS-level sandbox. This removes a primary
	// exploit mitigation barrier and should only be set in containerized or
	// CI environments where the sandbox cannot be enabled (e.g., Docker
	// without --cap-add SYS_ADMIN). The sandbox is also disabled when the
	// VESPASIAN_NO_SANDBOX environment variable is set to "true".
	NoSandbox bool

	// ChromePath overrides the Chrome binary used by the launcher. This value
	// is passed directly to exec.Command — it must be a trusted, hardcoded
	// path. Never populate from user-controlled input.
	ChromePath string

	// AllowBrowserDownload permits go-rod to download a managed Chromium from
	// its third-party mirror hosts (Google Storage, npmmirror, Playwright CDN)
	// when no system browser is found and ChromePath is unset. It is OFF by
	// default: configureLauncher pins the system browser via launcher.LookPath()
	// and errors when none is found, so a security crawl never pulls a browser
	// binary over the network (supply-chain hardening, LAB-4999). Enable it — or
	// set VESPASIAN_ALLOW_BROWSER_DOWNLOAD=true — only for local dev on platforms
	// without a system Chrome (e.g. arm64 Linux, where Google Chrome has no build).
	AllowBrowserDownload bool

	// Proxy sets the Chrome --proxy-server flag, routing all browser traffic
	// through the given address (e.g., "http://127.0.0.1:8080" for Burp Suite).
	Proxy string
}

// BrowserManager owns the Chrome process lifecycle. It launches Chrome via
// go-rod's launcher and retains the handle so vespasian can kill the browser
// immediately on signal, stopping all outbound requests.
type BrowserManager struct {
	launcher    *launcher.Launcher
	browser     *rod.Browser
	wsEndpoint  string
	killOnce    sync.Once
	cleanupOnce sync.Once
}

// configureLauncher applies BrowserOptions to a new launcher without
// launching Chrome. Disables the sandbox when opts.NoSandbox is set or
// when the VESPASIAN_NO_SANDBOX env var is "true" (set by CI workflows).
func configureLauncher(opts BrowserOptions) (*launcher.Launcher, error) {
	l := launcher.New().
		Headless(opts.Headless)

	if opts.NoSandbox || os.Getenv("VESPASIAN_NO_SANDBOX") == "true" {
		l = l.NoSandbox(true)
	}
	if err := pinBrowserBinary(l, opts); err != nil {
		return nil, err
	}
	disableChromeTelemetry(l)
	if opts.Proxy != "" {
		if err := ValidateProxyAddr(opts.Proxy); err != nil {
			return nil, err
		}
		l = l.Set("proxy-server", opts.Proxy)
	}

	return l, nil
}

// pinBrowserBinary sets the launcher's browser binary so go-rod uses a local
// Chrome and never auto-downloads one (Finding 1, LAB-4999). By default go-rod
// leaves the binary unset and, at launch, downloads a managed Chromium from
// third-party mirror hosts (storage.googleapis.com, registry.npmmirror.com,
// playwright.*) — a supply-chain risk and a source of nondeterministic CI
// egress. go-rod does NOT auto-discover a system Chrome; LookPath() is a
// separate helper the launcher never calls on its own.
//
// Resolution order:
//  1. opts.ChromePath, if set, is used verbatim.
//  2. otherwise the system browser is resolved via launcher.LookPath() (whose
//     Linux candidates include /usr/bin/google-chrome-stable, the CI runner's
//     Chrome).
//  3. if none is found, return an error rather than let go-rod download —
//     UNLESS downloads are explicitly opted in via opts.AllowBrowserDownload or
//     VESPASIAN_ALLOW_BROWSER_DOWNLOAD=true, in which case the binary is left
//     unset so go-rod falls back to its managed download (keeps local dev
//     working on platforms with no system Chrome, e.g. arm64 Linux).
func pinBrowserBinary(l *launcher.Launcher, opts BrowserOptions) error {
	if opts.ChromePath != "" {
		l.Bin(opts.ChromePath)
		return nil
	}
	if path, found := browserLookPath(); found {
		l.Bin(path)
		return nil
	}
	if opts.AllowBrowserDownload || os.Getenv("VESPASIAN_ALLOW_BROWSER_DOWNLOAD") == "true" {
		// Leave the binary unset so go-rod downloads a managed browser.
		return nil
	}
	return fmt.Errorf("no system Chrome/Chromium found in standard paths: set BrowserOptions.ChromePath, install a browser, or set VESPASIAN_ALLOW_BROWSER_DOWNLOAD=true to allow go-rod to download one")
}

// disableChromeTelemetry adds launch flags that stop Chrome from phoning home
// to Google during a crawl (Finding 2, LAB-4999). go-rod's defaults already
// set --disable-background-networking and --disable-sync, but Chrome still
// reaches component-update, domain-reliability, optimization-hints and autofill
// endpoints — including dynamically-sharded *.gvt1.com hosts that make a CI
// egress allowlist brittle. These flags suppress that chatter without affecting
// the crawl.
func disableChromeTelemetry(l *launcher.Launcher) {
	l.Set("disable-component-update")
	l.Set("disable-domain-reliability")
	l.Set("no-pings")
	// Append, not Set: go-rod seeds disable-features with site-per-process and
	// TranslateUI (see launcher.New), which must be preserved.
	l.Append("disable-features", "OptimizationHints", "AutofillServerCommunication")
}

// NewBrowserManager launches a Chrome instance with the given options and
// returns a manager that owns its lifecycle.
func NewBrowserManager(opts BrowserOptions) (*BrowserManager, error) {
	l, err := configureLauncher(opts)
	if err != nil {
		return nil, err
	}

	wsURL, err := l.Launch()
	if err != nil {
		return nil, err
	}

	browser := rod.New().ControlURL(wsURL)
	if err := browser.Connect(); err != nil {
		l.Kill()
		l.Cleanup()
		return nil, fmt.Errorf("connect to browser: %w", err)
	}

	return &BrowserManager{
		launcher:   l,
		browser:    browser,
		wsEndpoint: wsURL,
	}, nil
}

// wsURL returns the Chrome DevTools Protocol WebSocket URL. The headless crawl
// engine (go-rod) connects to this URL instead of launching its own browser,
// so vespasian owns the Chrome process lifecycle.
//
// Security: this URL grants full control of the browser session. Do not
// log it or expose it to untrusted callers.
func (b *BrowserManager) wsURL() string {
	return b.wsEndpoint
}

// Kill immediately terminates the Chrome process. This stops all outbound
// network requests. Safe to call multiple times.
func (b *BrowserManager) Kill() {
	b.killOnce.Do(func() {
		b.launcher.Kill()
	})
}

// cleanup waits for Chrome to exit and removes the temporary user data
// directory. Safe to call multiple times.
func (b *BrowserManager) cleanup() {
	b.cleanupOnce.Do(func() {
		b.launcher.Cleanup()
	})
}

// Close kills Chrome (if still running) and cleans up resources. Intended
// for use with defer in the normal (non-signal) path.
func (b *BrowserManager) Close() {
	if b.browser != nil {
		// #nosec G104 -- best-effort close on a process that may already be dead; any error is unactionable and the subsequent Kill() + cleanup() still execute.
		b.browser.Close() //nolint:errcheck,gosec // best-effort; process may already be dead
	}
	b.Kill()
	b.cleanup()
}

// SetCookies injects cookies into Chrome's cookie store via the Storage.setCookies
// CDP protocol. This is the reliable way to propagate session cookies across all
// browser requests — unlike Network.setExtraHTTPHeaders, cookies set via the
// Storage domain survive redirects, new tabs, and Fetch API interception.
func (b *BrowserManager) SetCookies(cookies []*proto.NetworkCookieParam) error {
	if b == nil || b.browser == nil {
		return fmt.Errorf("browser not connected")
	}
	return b.browser.SetCookies(cookies)
}

// PID returns the Chrome process ID, useful for testing.
func (b *BrowserManager) PID() int {
	return b.launcher.PID()
}

// ValidateProxyAddr checks that the proxy address is a valid http/https/socks5
// URL with a host and no embedded credentials. It is used by both crawler
// backends: the headless path (NewBrowserManager, for the Chrome
// --proxy-server flag) and the HTTP path (HTTPCrawler.Crawl and the CLI's
// doCrawl, before opts.Proxy is printed) so a bad or credential-bearing proxy
// is rejected before any network activity or logging.
func ValidateProxyAddr(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid proxy address: %w", err)
	}
	// Check credentials first — later error messages include the address,
	// so we must reject (and redact) credentials before reaching them.
	if u.User != nil {
		// Redact credentials manually — u.Redacted() preserves the username
		// and shows the password as "xxxxx", but we want both fully masked
		// so neither leaks into logs, CI output, or terminal scrollback.
		u.User = url.UserPassword("xxxxx", "xxxxx")
		return fmt.Errorf("invalid proxy address %q: embedded credentials are not supported (they would be visible in process listing); configure authentication in your proxy instead", u.String())
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" {
		return fmt.Errorf("invalid proxy address %q: scheme must be http, https, or socks5", addr)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid proxy address %q: missing host", addr)
	}
	return nil
}
