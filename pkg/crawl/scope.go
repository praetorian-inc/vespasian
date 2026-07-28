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
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"

	"github.com/praetorian-inc/vespasian/pkg/ssrf"
)

// isPrivateIP reports whether ip falls within a private or internal network.
// It delegates to pkg/ssrf.IsPrivateIP, which is the single source of truth
// for the CIDR list shared by the crawl and probe stages.
func isPrivateIP(ip net.IP) bool {
	return ssrf.IsPrivateIP(ip)
}

// isPrivateHost resolves a hostname via DNS and returns true if any of the
// resolved IPs are private/internal. Also returns true for raw IP addresses
// in private ranges. This prevents the browser from navigating to internal
// network endpoints (SSRF protection).
func isPrivateHost(hostname string) bool {
	// Check if it's already a raw IP address.
	if ip := net.ParseIP(hostname); ip != nil {
		return isPrivateIP(ip)
	}

	// Resolve and check all addresses.
	addrs, err := net.LookupHost(hostname) //nolint:gosec // G704: intentional SSRF protection — taint flows to isPrivateHost check below
	if err != nil {
		// DNS failure — reject to be safe.
		return true
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && isPrivateIP(ip) {
			return true
		}
	}
	return false
}

// scopeChecker returns a function that checks whether a URL is in scope
// relative to the seed URL, based on the scope policy. Unless allowPrivate
// is true, URLs that resolve to private/internal IP addresses are rejected
// to prevent SSRF attacks when the crawl engine runs as a service component.
//
// Scope policies:
//   - "same-origin": exact scheme + host + port match
//   - "same-domain": registered domain match, allowing subdomains
func scopeChecker(seedURL string, scope string, allowPrivate bool) (func(string) bool, error) {
	seed, err := url.Parse(seedURL)
	if err != nil {
		return nil, fmt.Errorf("parse seed URL: %w", err)
	}
	if seed.Host == "" {
		return nil, fmt.Errorf("seed URL has no host: %q", seedURL)
	}

	// ssrfCheck returns false (reject) if the URL resolves to a private IP.
	ssrfCheck := func(u *url.URL) bool {
		if allowPrivate {
			return true
		}
		return !isPrivateHost(u.Hostname())
	}

	switch scope {
	case "same-domain":
		seedDomain, err := registeredDomain(seed.Hostname())
		if err != nil {
			return nil, fmt.Errorf("extract registered domain: %w", err)
		}
		return func(rawURL string) bool {
			u := parseHTTPURL(rawURL)
			if u == nil {
				return false
			}
			d, err := registeredDomain(u.Hostname())
			if err != nil {
				return false
			}
			return strings.EqualFold(d, seedDomain) && ssrfCheck(u)
		}, nil

	default: // "same-origin" and any unknown value
		seedOrigin := seed.Scheme + "://" + seed.Host
		return func(rawURL string) bool {
			u := parseHTTPURL(rawURL)
			if u == nil {
				return false
			}
			return (u.Scheme+"://"+u.Host) == seedOrigin && ssrfCheck(u)
		}, nil
	}
}

// seedScope is the crawl's scope predicate plus a one-shot widening to the origin
// the SEED URL actually resolved to after redirects.
//
// Why it exists: an operator who seeds http://example.com against a server that
// 302s to https://example.com (or apex → www) gets a crawl where Chrome follows
// the redirect and every CDP-captured request carries the POST-redirect origin.
// The same-origin predicate compares "scheme://host" exactly, so it rejected all
// of them and the run produced an empty capture with exit code 0 and no
// diagnostic. Learning the seed's effective origin is what makes the common
// "http → https" and "apex → www" deployments crawlable at all.
//
// CONTAINMENT. Scope is an engagement containment control, so the widening is
// deliberately narrow and auditable:
//
//  1. Only the SEED's own navigation can widen scope. LearnEffectiveOrigin is
//     called from the depth-0 page visit and nowhere else, so a redirect issued
//     by some arbitrary page deeper in the crawl — which an attacker-controlled
//     page could trigger at will — never widens anything.
//  2. It is one-shot and adds exactly ONE origin: the scheme://host the seed
//     resolved to. It is not a domain-level relaxation, and a second call (a
//     resumed depth-0 entry, a retry) cannot add another origin.
//  3. The learned origin must share the seed's REGISTRABLE DOMAIN. http→https and
//     apex→www always do; an IdP hand-off, an open redirect on the seed, or any
//     other foreign-domain target does not, and is refused. Without this the
//     widening turned one redirect into crawl scope the operator never authorized,
//     defeating --scope as a containment control (Codex review, PR #189).
//  4. The SSRF gate still applies. A seed that redirects to 127.0.0.1,
//     169.254.169.254, or any RFC1918 address is refused unless the operator
//     passed --dangerous-allow-private, exactly as for the seed itself. The
//     verdict is taken once, at learn time, not per URL.
//  5. The widening is announced on stderr, so the operator sees the effective
//     scope of the run instead of silently getting a wider crawl.
//
// This applies to the headless backend only. On the net/http backend
// redirectScopeGuard rejects the cross-origin redirect during the seed fetch and
// the failure is already reported on stderr, so that path is loud rather than
// silent; widening it would mean letting a redirect through the guard before the
// guard has decided, which is a change to the control itself and out of scope here.
type seedScope struct {
	base         func(string) bool // policy predicate from scopeChecker (origin/domain match + SSRF)
	allowPrivate bool
	seedOrigin   string
	stderr       io.Writer

	mu        sync.RWMutex
	learned   bool   // LearnEffectiveOrigin already ran (one-shot)
	effOrigin string // the seed's post-redirect origin, "" when it matched seedOrigin
}

// newSeedScope builds the scope predicate for a crawl of seedURL. It wraps
// [scopeChecker] with the seed-effective-origin widening documented on
// [seedScope]. stderr may be nil to suppress the widening notice.
func newSeedScope(seedURL, scope string, allowPrivate bool, stderr io.Writer) (*seedScope, error) {
	base, err := scopeChecker(seedURL, scope, allowPrivate)
	if err != nil {
		return nil, err
	}
	// originOf (jsreplay.go) is the shared origin canonicalizer: lowercased
	// scheme/host with the default port made explicit, so the implicit- and
	// explicit-port forms of the same origin compare equal. scopeChecker already
	// rejected a seed without a host, so this cannot be "".
	seedOrigin := originOf(seedURL)
	if seedOrigin == "" {
		return nil, fmt.Errorf("seed URL has no origin: %q", redactSeedURL(seedURL))
	}
	return &seedScope{
		base:         base,
		allowPrivate: allowPrivate,
		seedOrigin:   seedOrigin,
		stderr:       stderr,
	}, nil
}

// Check reports whether rawURL is in scope: either the configured policy accepts
// it, or it is on the seed's learned effective origin, which cleared the domain
// and SSRF gates once at learn time.
func (s *seedScope) Check(rawURL string) bool {
	if s.base(rawURL) {
		return true
	}
	s.mu.RLock()
	eff := s.effOrigin
	s.mu.RUnlock()
	if eff == "" {
		return false
	}
	// A plain string comparison: the effective origin already cleared the domain
	// and private-host gates in LearnEffectiveOrigin, and it is a single fixed
	// host whose verdict cannot change within a run. Re-running isPrivateHost here
	// re-did an unbounded, uncached net.LookupHost on the per-captured-request
	// scope hot path, and s.base had already paid for one lookup before returning
	// false (CodeRabbit review, PR #189).
	return originOf(rawURL) == eff
}

// LearnEffectiveOrigin records the origin the seed page actually resolved to and,
// when it differs from the seed's own origin, extends the accepted set by that one
// origin. It is one-shot: every call after the first is ignored, so only the
// seed's first navigation can widen the crawl. A private effective origin is
// refused (and reported) unless the operator opted in with --dangerous-allow-private.
func (s *seedScope) LearnEffectiveOrigin(effectiveURL string) {
	u := parseHTTPURL(effectiveURL)
	if u == nil {
		return
	}
	origin := originOf(effectiveURL)

	// Claim the one-shot under the lock, then RELEASE it before the domain and
	// private-host checks. isPrivateHost is an unbounded, uncached net.LookupHost;
	// holding the exclusive lock across it blocked every concurrent Check for the
	// whole resolution. The learned flag already guarantees only one caller gets
	// past here, so the checks need no lock — it is only reacquired to publish the
	// result (CodeRabbit review, PR #189).
	s.mu.Lock()
	if s.learned {
		s.mu.Unlock()
		return
	}
	s.learned = true
	s.mu.Unlock()

	if origin == s.seedOrigin {
		return
	}
	// The widening exists for http→https and apex→www, which are always the SAME
	// registrable domain. A redirect to a FOREIGN domain is a different thing: an
	// IdP hand-off, an open redirect on the seed, or an attacker-controlled
	// target. Admitting it would turn one redirect into crawl scope the operator
	// never authorized, defeating --scope as a containment control. Constrain the
	// learned origin to the seed's registrable domain before publishing it
	// (Codex review, PR #189).
	if !s.sameRegistrableDomain(u.Hostname()) {
		if s.stderr != nil {
			fmt.Fprintf(s.stderr, "scope: seed redirected to %s, a different domain than %s; not adding it to scope\n", //nolint:errcheck // best-effort status
				origin, s.seedOrigin)
		}
		return
	}
	// The SSRF decision is taken before publishing the origin so the operator is
	// never told the scope widened to a host the crawl will then refuse.
	if !s.allowPrivate && isPrivateHost(u.Hostname()) {
		if s.stderr != nil {
			fmt.Fprintf(s.stderr, "scope: seed redirected to private origin %s; not adding it to scope (pass %s to allow)\n", //nolint:errcheck // best-effort status
				origin, flagDangerousAllowPrivate)
		}
		return
	}
	s.mu.Lock()
	s.effOrigin = origin
	s.mu.Unlock()

	if s.stderr != nil {
		fmt.Fprintf(s.stderr, "scope: seed %s redirected to %s; treating that origin as in scope for this crawl\n", //nolint:errcheck // best-effort status
			s.seedOrigin, origin)
	}
}

// sameRegistrableDomain reports whether host shares the seed's registrable
// domain, which is the bound on how far the seed-redirect widening may reach.
//
// It falls back to an exact hostname match when either side has no registrable
// domain — an IP-literal or single-label seed such as http://127.0.0.1:8080 or
// http://localhost. That still permits the scheme-only case the widening exists
// for (http→https on the same host) while refusing to treat one bare host as
// equivalent to any other. The seed hostname is read from seedOrigin rather than
// stored separately so there is one source of truth for what the seed was.
func (s *seedScope) sameRegistrableDomain(host string) bool {
	seedHost := ""
	if u := parseHTTPURL(s.seedOrigin); u != nil {
		seedHost = u.Hostname()
	}
	if seedHost == "" || host == "" {
		return false
	}
	seedDomain, seedErr := registeredDomain(seedHost)
	hostDomain, hostErr := registeredDomain(host)
	if seedErr != nil || hostErr != nil {
		return strings.EqualFold(seedHost, host)
	}
	return strings.EqualFold(seedDomain, hostDomain)
}

// parseHTTPURL parses a URL and returns nil if it is invalid or not HTTP(S).
func parseHTTPURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil
	}
	return u
}

// registeredDomain extracts the eTLD+1 (registered domain) from a hostname.
// For example, "api.example.com" returns "example.com".
func registeredDomain(host string) (string, error) {
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", err
	}
	return domain, nil
}

// ssrfSafeDialContext is a net.Dialer DialContext replacement that re-resolves
// the target host and rejects the connection if any resolved IP is private or
// internal (SSRF protection). By performing the IP check at dial time — not
// only in the upfront scope/SSRF check — it closes the DNS-rebinding TOCTOU
// window: a short-TTL domain that resolves to a public IP during the scope
// check can be re-resolved to 127.0.0.1 or another private address by the
// time client.Do actually dials the connection.
//
// It delegates to pkg/ssrf.SafeDialContext, which is the shared implementation
// used by both pkg/crawl and pkg/probe.
func ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return ssrf.SafeDialContext(ctx, network, addr)
}

// frontierKey returns the crawl-frontier dedup key for rawURL: the canonicalized
// URL with its query string removed (LAB-4678 Phase 1). Two links differing only
// in query parameters (e.g. /product?id=1 and /product?id=2) collapse to one
// key, so the crawler visits the page template once instead of spending the page
// budget on near-duplicate variants — a driver of run-to-run truncation
// variance. The queued entry keeps the original URL, so the first variant is
// still fetched with its parameters, and passive capture still records every
// distinct-parameter request for classification; only re-crawling of the same
// template is suppressed. Tradeoff: paginated query templates (?page=N) are
// visited once.
func frontierKey(rawURL string) string {
	return canonicalizeURL(rawURL, true)
}

// canonicalizeURL lowercases scheme and host, strips the fragment and any
// default port, and — when stripQuery is set — removes the query string.
// Returns "" on a parse error.
func canonicalizeURL(rawURL string, stripQuery bool) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.Fragment = ""
	if stripQuery {
		u.RawQuery = ""
	}
	u.Host = strings.ToLower(u.Host)
	u.Scheme = strings.ToLower(u.Scheme)

	// Remove default ports to avoid treating example.com and example.com:443 as different.
	hostname := u.Hostname()
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		u.Host = hostname
	}

	return u.String()
}
