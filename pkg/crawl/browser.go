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
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// BrowserOptions configures Chrome launch parameters.
type BrowserOptions struct {
	Headless bool

	// NoSandbox disables Chrome's OS-level sandbox. This removes a primary
	// exploit mitigation barrier and should only be set in containerized or
	// CI environments where the sandbox cannot be enabled (e.g., Docker
	// without --cap-add SYS_ADMIN).
	NoSandbox bool

	// ChromePath overrides the Chrome binary used by the launcher. This value
	// is passed directly to exec.Command — it must be a trusted, hardcoded
	// path. Never populate from user-controlled input.
	ChromePath string

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

// NewBrowserManager launches a Chrome instance with the given options and
// returns a manager that owns its lifecycle.
func NewBrowserManager(opts BrowserOptions) (*BrowserManager, error) {
	l := launcher.New().
		Headless(opts.Headless)

	if opts.NoSandbox {
		l = l.NoSandbox(true)
	}
	if opts.ChromePath != "" {
		l = l.Bin(opts.ChromePath)
	}
	if opts.Proxy != "" {
		if err := validateProxyAddr(opts.Proxy); err != nil {
			return nil, err
		}
		l = l.Set("proxy-server", opts.Proxy)
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

// wsURL returns the Chrome DevTools Protocol WebSocket URL. Pass this to
// Katana's ChromeWSUrl option so it connects to our browser instead of
// launching its own.
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
	b.Kill()
	b.cleanup()
}

// SetCookies injects cookies into Chrome's cookie store via the Storage.setCookies
// CDP protocol. This is the reliable way to propagate session cookies across all
// browser requests — unlike Network.setExtraHTTPHeaders, cookies set via the
// Storage domain survive redirects, new tabs, and Fetch API interception.
func (b *BrowserManager) SetCookies(cookies []*proto.NetworkCookieParam) error {
	if b.browser == nil {
		return fmt.Errorf("browser not connected")
	}
	return b.browser.SetCookies(cookies)
}

// PID returns the Chrome process ID, useful for testing.
func (b *BrowserManager) PID() int {
	return b.launcher.PID()
}

// validateProxyAddr checks that the proxy address is a valid HTTP/HTTPS URL
// with a host and port. This prevents typos from producing confusing Chrome
// launch errors and ensures no credentials are embedded in the URL.
func validateProxyAddr(addr string) error {
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
