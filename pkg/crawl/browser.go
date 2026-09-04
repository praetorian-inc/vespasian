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

// browserLookPath is a var so tests can hit the no-browser-found path whatever
// the host has installed.
//
// NOT PARALLEL-SAFE: tests swap it (stubLookPath) and MUST NOT call t.Parallel().
// Unsynchronized because production reads it once per launcher config and the swap
// precedes the call under test.
var browserLookPath = launcher.LookPath

// BrowserOptions configures Chrome launch parameters.
type BrowserOptions struct {
	Headless bool

	// Removes a primary exploit mitigation. Only for containers that cannot
	// enable it (Docker without --cap-add SYS_ADMIN). VESPASIAN_NO_SANDBOX=true
	// does the same.
	NoSandbox bool

	// Passed straight to exec.Command: must be trusted and hardcoded, never
	// user-controlled.
	ChromePath string

	// Lets go-rod pull a Chromium from third-party mirrors (Google Storage,
	// npmmirror, Playwright CDN). OFF by default so a security crawl never fetches
	// a browser binary over the network (LAB-4999). For local dev on platforms with
	// no system Chrome, e.g. arm64 Linux.
	AllowBrowserDownload bool

	Proxy string // Chrome --proxy-server, e.g. "http://127.0.0.1:8080"
}

// BrowserManager owns the Chrome process lifecycle, retaining the launcher handle
// so a signal can kill the browser and stop all outbound requests at once.
type BrowserManager struct {
	launcher    *launcher.Launcher
	browser     *rod.Browser
	wsEndpoint  string
	killOnce    sync.Once
	cleanupOnce sync.Once
}

// vespasianEnablesNoSandbox is the single source of truth for the sandbox
// decision. Separate from the launcher's own state because go-rod's
// launcher.New() adds --no-sandbox by default in containers, which masks the flag
// as observed on the launcher (LAB-4994). Kept a separate helper so
// TestConfigureLauncher can assert this decision directly; the launcher-baseline
// assertion beside it goes vacuous in a container.
func vespasianEnablesNoSandbox(opts BrowserOptions) bool {
	return opts.NoSandbox || os.Getenv("VESPASIAN_NO_SANDBOX") == "true"
}

// configureLauncher applies BrowserOptions without launching Chrome.
func configureLauncher(opts BrowserOptions) (*launcher.Launcher, error) {
	l := launcher.New().
		Headless(opts.Headless)

	if vespasianEnablesNoSandbox(opts) {
		l = l.NoSandbox(true)
	}
	// Before pinning, so a bad proxy reports as a proxy error even on a host with
	// no Chrome, rather than being masked by "no system browser".
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

// pinBrowserBinary stops go-rod auto-downloading a browser (LAB-4999). Left
// unset it fetches a managed Chromium from third-party mirrors
// (storage.googleapis.com, registry.npmmirror.com, playwright.*), a supply-chain
// risk and nondeterministic CI egress. go-rod does NOT auto-discover a system
// Chrome — LookPath() is a helper the launcher never calls itself.
//
// ChromePath, else LookPath(), else error unless downloads are opted in.
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
		return nil // unset: go-rod downloads a managed browser
	}
	return fmt.Errorf("no system Chrome/Chromium found in standard paths: set BrowserOptions.ChromePath, install a browser, or set VESPASIAN_ALLOW_BROWSER_DOWNLOAD=true to allow go-rod to download one")
}

// chromeEgressSink is where URL-override flags point. ".invalid" is RFC 2606
// reserved and never resolves, so an override fails at NXDOMAIN with no handshake.
// The distinct path/port suffixes below are cosmetic.
const chromeEgressSink = "https://vespasian-blocked.invalid"

// disableChromeTelemetry stops Chrome phoning home during a crawl (LAB-4999).
// go-rod already sets --disable-background-networking and --disable-sync, but
// Chrome still reaches component-update, domain-reliability, optimization-hints
// and autofill, including sharded *.gvt1.com hosts that make a CI egress
// allowlist brittle.
//
// Tradeoff: --disable-component-update also stops in-crawl CRLSet and
// Safe-Browsing list refreshes, so the build-time CRLSet stands for the crawl.
// Accepted: OS-trust-store TLS verification and the SSRF/scope guards remain.
//
// A live harden-runner audit of branded google-chrome-stable showed the above
// insufficient — it still reached accounts.google.com (13x), www.google.com,
// clients2.google.com, android.clients.google.com, mtalk.google.com:5228 and
// safebrowsingohttpgateway.googleapis.com. The flags below target each.
//
// Most are URL overrides, not booleans: Chrome builds the request against a
// compiled-in host and the switch is the only verified lever, so redirecting to
// chromeEgressSink is how egress stops where no "disable" exists. This covers
// only Chrome's own browser-process requests, never a page's own JavaScript
// hitting accounts.google.com, which the crawl must still observe.
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
	// Append, not Set: go-rod seeds this with site-per-process and TranslateUI.
	l.Append("disable-features", "OptimizationHints", "AutofillServerCommunication", "SafeBrowsingHashPrefixRealTimeLookups")

	l.Set("gaia-url", chromeEgressSink)
	l.Set("gcm-checkin-url", chromeEgressSink+"/checkin")
	l.Set("gcm-registration-url", chromeEgressSink+"/register")
	l.Set("gcm-mcs-endpoint", chromeEgressSink+":5228")
	l.Set("apps-gallery-update-url", chromeEgressSink+"/no-extension-updates")
}

// NewBrowserManager launches Chrome and owns its lifecycle.
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

// wsURL is the CDP endpoint the engine connects to instead of launching its own
// browser. It grants full control of the session: never log or expose it.
func (b *BrowserManager) wsURL() string {
	return b.wsEndpoint
}

// Kill terminates Chrome, stopping all outbound requests. Idempotent.
func (b *BrowserManager) Kill() {
	b.killOnce.Do(func() {
		b.launcher.Kill()
	})
}

// cleanup waits for exit and removes the temp user-data dir. Idempotent.
func (b *BrowserManager) cleanup() {
	b.cleanupOnce.Do(func() {
		b.launcher.Cleanup()
	})
}

// Close kills Chrome and cleans up. For defer on the non-signal path.
func (b *BrowserManager) Close() {
	if b.browser != nil {
		// #nosec G104 -- may already be dead; Kill() and cleanup() still run.
		b.browser.Close() //nolint:errcheck,gosec // best-effort; process may already be dead
	}
	b.Kill()
	b.cleanup()
}

// SetCookies goes through CDP Storage.setCookies, not
// Network.setExtraHTTPHeaders: only those survive redirects, new tabs and
// page-initiated fetch().
func (b *BrowserManager) SetCookies(cookies []*proto.NetworkCookieParam) error {
	if b == nil || b.browser == nil {
		return fmt.Errorf("browser not connected")
	}
	return b.browser.SetCookies(cookies)
}

// PID returns the Chrome process ID. Consumed only by the browser-lifecycle
// integration tests (TestBrowserManager_LaunchAndKill, TestBrowserManager_Close),
// which sit behind the `integration` build tag, so it has no production caller.
func (b *BrowserManager) PID() int {
	return b.launcher.PID()
}

// ValidateProxyAddr requires http/https/socks5, a host, and no credentials. Both
// backends call it before any network activity or logging of opts.Proxy.
func ValidateProxyAddr(addr string) error {
	// A proxy address carries no userinfo, so any '@' means credentials. Mask
	// through the LAST '@' rather than parsing: userinfo always precedes it, so no
	// password reaches logs whatever it contains ('/', '?', '#', '%', '://', more
	// '@'s) that a structure-aware scan could misread. With no '@' the errors below
	// may echo addr safely.
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
