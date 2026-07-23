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
	"strings"
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// browserLookPath resolves the system browser binary. It is a package var so
// tests can exercise the no-browser-found path deterministically regardless of
// what is installed on the host (go-rod uses the same "interface for testing"
// idiom for its own exec calls). Production code always uses launcher.LookPath.
//
// NOT PARALLEL-SAFE: tests swap this via a t.Cleanup-restored pattern (see
// stubLookPath in browser_test.go) and MUST NOT call t.Parallel() — concurrent
// swaps would race on the global. No sync is used here because the production
// read path runs once per launcher configuration and the test swap happens
// before the call under test.
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

// vespasianEnablesNoSandbox reports whether Vespasian's own configuration opts
// into disabling Chrome's OS-level sandbox — either explicitly via
// BrowserOptions.NoSandbox or via the VESPASIAN_NO_SANDBOX env var (set by CI
// workflows). It is the single source of truth for that decision; both
// configureLauncher and browser_test.go consult it. Keeping the decision in a
// self-contained helper lets the test assert Vespasian's contribution
// directly, which stays deterministic even where go-rod's launcher.New() adds
// --no-sandbox by default in containers and masks the launcher-observed flag
// (LAB-4994).
func vespasianEnablesNoSandbox(opts BrowserOptions) bool {
	return opts.NoSandbox || os.Getenv("VESPASIAN_NO_SANDBOX") == "true"
}

// configureLauncher applies BrowserOptions to a new launcher without
// launching Chrome. In order, it:
//
//  1. Disables the sandbox when vespasianEnablesNoSandbox opts in — i.e.
//     opts.NoSandbox is set or VESPASIAN_NO_SANDBOX is "true" (see that
//     helper's doc for the exact condition, incl. go-rod's container default;
//     LAB-4994).
//  2. Validates opts.Proxy (when set) via ValidateProxyAddr before touching
//     the browser binary, so a bad proxy is always reported as a proxy error
//     independent of what Chrome is installed on the host.
//  3. Pins the browser binary via pinBrowserBinary, which returns a "no system
//     Chrome/Chromium found" error when no browser is resolvable — unless
//     downloads are opted in via opts.AllowBrowserDownload or
//     VESPASIAN_ALLOW_BROWSER_DOWNLOAD=true (Finding 1, LAB-4999). This is a
//     new failure mode unrelated to the sandbox.
//  4. Applies telemetry/phone-home-disabling launch flags via
//     disableChromeTelemetry (Finding 2, LAB-4999).
func configureLauncher(opts BrowserOptions) (*launcher.Launcher, error) {
	l := launcher.New().
		Headless(opts.Headless)

	if vespasianEnablesNoSandbox(opts) {
		l = l.NoSandbox(true)
	}
	// Validate the proxy before resolving the browser binary. Proxy validation
	// is a deterministic check on caller input; pinning depends on what is
	// installed on the host. Ordering validation first keeps error behavior
	// host-independent — a bad proxy is always reported as a proxy error, even
	// on a machine without a system Chrome — instead of masking it behind a
	// "no system browser" error (LAB-4999 review feedback).
	if opts.Proxy != "" {
		if err := ValidateProxyAddr(opts.Proxy); err != nil {
			return nil, err
		}
		l = l.Set("proxy-server", opts.Proxy)
	}
	if err := pinBrowserBinary(l, opts); err != nil {
		return nil, err
	}
	disableChromeTelemetry(l)

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

// chromeEgressSink is a destination for launch flags that redirect a Chrome
// subsystem's endpoint rather than toggle a boolean switch. It resolves to
// nothing: ".invalid" is reserved by RFC 2606 and is guaranteed to never
// resolve on the public Internet, so pointing a Google-service URL override
// here fails fast (NXDOMAIN, no TCP/TLS handshake) instead of reaching any
// real host. Distinct path/port suffixes below are cosmetic (readability of
// any dropped-connection diagnostics), not functionally required.
const chromeEgressSink = "https://vespasian-blocked.invalid"

// disableChromeTelemetry adds launch flags that stop Chrome from phoning home
// to Google during a crawl (Finding 2, LAB-4999). go-rod's defaults already
// set --disable-background-networking and --disable-sync, but Chrome still
// reaches component-update, domain-reliability, optimization-hints and autofill
// endpoints — including dynamically-sharded *.gvt1.com hosts that make a CI
// egress allowlist brittle. These flags suppress that chatter without affecting
// the crawl.
//
// Tradeoff: --disable-component-update also stops in-crawl CRLSet and
// Safe-Browsing list refreshes, so Chrome relies on the build-time CRLSet for
// the crawl's duration. Accepted for short-lived, operator-initiated crawls —
// full TLS chain verification against the OS trust store and the SSRF/scope
// guards remain in force (LAB-4999).
//
// A live step-security/harden-runner egress audit of branded google-chrome-stable
// (LAB-4999 review) found the flags above insufficient: even with them set,
// branded Chrome still phoned home to accounts.google.com (13x — the primary
// target below), www.google.com, clients2.google.com,
// android.clients.google.com, mtalk.google.com:5228, and
// safebrowsingohttpgateway.googleapis.com. The flags below target each of
// those hosts individually. Unlike the boolean switches above, most of these
// are URL-override switches: Chrome's C++ browser-process code builds a
// request against a compiled-in default host, and reading a command-line
// switch to override that default is the only verified lever for that
// subsystem. Redirecting to chromeEgressSink (see above) suppresses the
// egress without a boolean "disable" existing for that host. These only
// affect Chrome's own browser-process requests — not renderer-initiated
// requests a crawled page's own JavaScript makes to accounts.google.com
// (e.g. a real "Sign in with Google" button), which the crawler must still
// observe.
//
//   - --gaia-url redirects accounts.google.com, Chrome's own GAIA/account-
//     consistency origin (google_apis/gaia/gaia_urls.cc: kDefaultGaiaUrl is
//     "https://accounts.google.com", overridden via switches::kGaiaUrl when
//     the switch is set — google_apis/gaia/gaia_switches.cc).
//   - --gcm-checkin-url and --gcm-registration-url redirect
//     android.clients.google.com's /checkin and /c2dm/register3 endpoints
//     (google_apis/gcm/engine/gservices_settings.cc: kDefaultCheckinURL,
//     kDefaultRegistrationURL; switches defined in
//     google_apis/gcm/engine/gservices_switches.cc).
//   - --gcm-mcs-endpoint redirects the GCM Mobile Connection Server's
//     persistent connection, normally mtalk.google.com:5228. The switch value
//     is parsed as a full URL, not a bare host:port: GServicesSettings::
//     GetMCSMainEndpoint returns GURL(GetSwitchValueASCII(kGCMMCSEndpoint))
//     verbatim (google_apis/gcm/engine/gservices_settings.cc), matching
//     Chrome's own default which is built from kMCSEnpointTemplate "https://%s:%d"
//     in the same file — so "https://…:5228" is the correct form, a present
//     switch is always honored, and there is no code path that falls back to
//     mtalk on a malformed value. Setting the switch also suppresses the
//     fallback endpoint that would otherwise be tried
//     (GServicesSettings::GetMCSFallbackEndpoint).
//   - --apps-gallery-update-url redirects the Chrome Web Store extension
//     update check away from clients2.google.com/service/update2/crx
//     (extension_urls::GetDefaultWebstoreUpdateUrl, overridden by
//     chrome/common/extensions/chrome_extensions_client.cc when
//     switches::kAppsGalleryUpdateURL, declared in
//     chrome/common/chrome_switches.cc, is set). This is a different
//     subsystem from Omaha component update (already covered above by
//     --disable-component-update), which is why clients2.google.com egress
//     persisted despite that flag.
//   - disable-features=SafeBrowsingHashPrefixRealTimeLookups turns off a
//     feature that is FEATURE_ENABLED_BY_DEFAULT
//     (components/safe_browsing/core/common/features.cc) and gates the OHTTP
//     key service (components/safe_browsing/core/browser/hashprefix_realtime/
//     ohttp_key_service.cc) that talks to safebrowsingohttpgateway.googleapis.com
//     (confirmed as that API's default_host in the public googleapis/googleapis
//     proto definitions). Tradeoff: disables Safe Browsing's privacy-preserving
//     real-time hash-prefix lookups for the crawl's duration; the standard
//     locally-cached hash-prefix list (unaffected) still provides baseline
//     protection. Applied to every crawl, not just CI — this is deliberate: an
//     automated headless crawler has no human to phish, must not let Safe-
//     Browsing interstitials interrupt assessment of intentionally-hostile
//     targets, and should not leak hashed target URLs to Google. Together with
//     the --disable-component-update CRLSet/list-refresh tradeoff above, the
//     reduced defense-in-depth is a reviewed, accepted posture (capability-pr-
//     review SEC-BE-001) tracked under LAB-4732's block-mode flip; it is
//     bounded by the retained TLS chain verification against the OS trust
//     store, the cached hash-prefix list, the SSRF/scope guards, and the
//     short-lived, operator-initiated nature of a crawl.
//
// Investigated and rejected: --safebrowsing-disable-auto-update was removed
// from Chromium in November 2017 and no longer exists — it would be silently
// ignored by current Chrome.
//
// Known gap: no reliable CLI switch was found for www.google.com. The one
// candidate, --google-url, defaults to "google.com" (not "www.google.com")
// and has a single low-confidence production consumer
// (google_apis/gaia/gaia_urls.cc), so it is not added here. Per the LAB-4999
// review (REQ-001), if a live audit still shows this host it is handled as a
// justified egress-allowlist entry in LAB-4732 (the ticket that owns the
// block-mode flip), not by a launch flag.
//
// This change has not been re-validated against a live step-security/harden-runner
// audit of branded Chrome — that verification is tracked under LAB-4732's
// block-mode flip, same as the flags above it.
func disableChromeTelemetry(l *launcher.Launcher) {
	l.Set("disable-component-update")
	l.Set("disable-domain-reliability")
	l.Set("no-pings")
	// Append, not Set: go-rod seeds disable-features with site-per-process and
	// TranslateUI (see launcher.New), which must be preserved.
	l.Append("disable-features", "OptimizationHints", "AutofillServerCommunication", "SafeBrowsingHashPrefixRealTimeLookups")

	l.Set("gaia-url", chromeEgressSink)
	l.Set("gcm-checkin-url", chromeEgressSink+"/checkin")
	l.Set("gcm-registration-url", chromeEgressSink+"/register")
	l.Set("gcm-mcs-endpoint", chromeEgressSink+":5228")
	l.Set("apps-gallery-update-url", chromeEgressSink+"/no-extension-updates")
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
	// A proxy address is scheme://host[:port] and legitimately carries no
	// userinfo, so treat any '@' as embedded credentials and reject it before
	// anything echoes addr. Mask everything up to and including the last '@':
	// userinfo always precedes the '@', so replacing that whole span with a
	// fixed placeholder makes it impossible for a password to reach logs, CI
	// output, or terminal scrollback — regardless of characters in the
	// credential ('/', '?', '#', '%', a literal '://', or extra '@'s) that a
	// structure-aware scan could misjudge. With no '@' the address cannot carry
	// credentials, so the errors below may safely echo it.
	if at := strings.LastIndexByte(addr, '@'); at >= 0 {
		masked := "xxxxx@" + addr[at+1:]
		return fmt.Errorf("invalid proxy address %q: embedded credentials are not supported (they would be visible in process listing); configure authentication in your proxy instead", masked)
	}
	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid proxy address: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" {
		return fmt.Errorf("invalid proxy address %q: scheme must be http, https, or socks5", addr)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid proxy address %q: missing host", addr)
	}
	return nil
}
