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

// isPrivateIP delegates to pkg/ssrf.IsPrivateIP, the single source for the CIDR
// list shared with the probe stage.
func isPrivateIP(ip net.IP) bool {
	return ssrf.IsPrivateIP(ip)
}

// isPrivateHost resolves the host and reports true if any address is private, as it
// does for a raw IP literal in a private range. This is the upfront check only — it
// cannot bind what Chrome later resolves, and the headless path has no dial-time
// revalidation (see crawlHeadless).
//
// Uncached. Prefer a [hostChecker] for anything on a per-URL path; this remains for
// one-shot call sites and for tests that assert the raw resolution behavior.
func isPrivateHost(hostname string) bool {
	return newHostChecker().isPrivate(hostname)
}

// maxHostVerdictCacheEntries bounds the memoization map. A crawl is scope-limited to
// one origin or one registrable domain, so the distinct-host count is small in
// practice; the cap exists so a wildcard-DNS target cannot grow the map without bound.
// Past the cap the checker still answers correctly, it just stops caching.
const maxHostVerdictCacheEntries = 4096

// hostChecker answers "is this hostname private?" and MEMOIZES the verdict per
// hostname for its own lifetime.
//
// Memoization is load-bearing rather than an optimization: the verdict comes from a
// blocking net.LookupHost that takes no context, and it sits on the per-URL scope
// path. urlFrontier.Restore calls the scope predicate once PER PENDING ENTRY, and
// LoadCheckpoint admits up to MaxCheckpointEntries (1,000,000), so an uncached
// checker made resume startup stall for an unbounded, uninterruptible wall-clock
// period on work that is one lookup per distinct host (LAB-4678, SEC-BE-003).
//
// lookupHost is a field so tests can supply a deterministic resolver instead of
// depending on the environment's DNS. A crawl builds one checker, so a verdict is
// cached for the run and not across runs, which keeps the staleness window to a
// single crawl.
//
// What backs that window differs by backend, which is why it is stated rather than
// called a pre-filter. On the net/http backend pkg/ssrf's SafeDialContext re-resolves
// at connect time and is what actually defeats DNS rebinding. On the HEADLESS backend
// Chrome does its own dialing, so SafeDialContext never runs and this verdict is the
// only DNS-derived gate; memoizing widens its staleness window from per-check to
// per-run. The TOCTOU is not introduced by memoization — Chrome re-resolves
// independently of any check Go made — but the run-length window is what this trades
// for bounding Restore's per-entry resolution cost.
type hostChecker struct {
	lookupHost func(string) ([]string, error)

	mu      sync.Mutex
	verdict map[string]bool
}

// newHostChecker returns a hostChecker backed by the system resolver.
func newHostChecker() *hostChecker {
	return &hostChecker{
		lookupHost: net.LookupHost,
		verdict:    make(map[string]bool),
	}
}

// isPrivate reports whether hostname is a raw private IP or resolves to one.
// A DNS failure is reported as private: rejecting on an unresolvable host fails
// closed, which is the safe direction for an SSRF gate.
func (h *hostChecker) isPrivate(hostname string) bool {
	// A raw IP needs no resolution and no cache entry.
	if ip := net.ParseIP(hostname); ip != nil {
		return isPrivateIP(ip)
	}

	h.mu.Lock()
	cached, ok := h.verdict[hostname]
	h.mu.Unlock()
	if ok {
		return cached
	}

	private := h.resolveIsPrivate(hostname)

	h.mu.Lock()
	if len(h.verdict) < maxHostVerdictCacheEntries {
		h.verdict[hostname] = private
	}
	h.mu.Unlock()
	return private
}

// resolveIsPrivate performs the resolution itself. Split out so the lookup is never
// held under h.mu: two goroutines racing on the same new hostname each pay one lookup,
// which is strictly better than serializing every caller behind the lock for the
// duration of a DNS round trip.
func (h *hostChecker) resolveIsPrivate(hostname string) bool {
	addrs, err := h.lookupHost(hostname) //nolint:gosec // G704: intentional SSRF protection — taint flows to isPrivateIP below
	if err != nil {
		// Fail closed.
		return true
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && isPrivateIP(ip) {
			return true
		}
	}
	return false
}

// scopeChecker returns an in-scope predicate. Unless allowPrivate, URLs resolving
// to private addresses are rejected, which matters when the engine runs as a
// service component.
//
//   - "same-origin": exact scheme, host and port
//   - "same-domain": registered domain, subdomains allowed
//
// The returned predicate memoizes private-host verdicts for its own lifetime; see
// [hostChecker].
func scopeChecker(seedURL string, scope string, allowPrivate bool) (func(string) bool, error) {
	return scopeCheckerWith(seedURL, scope, allowPrivate, newHostChecker())
}

// scopeCheckerWith is [scopeChecker] over a caller-supplied [hostChecker]. It
// exists so a caller that ALSO resolves hosts itself shares one memoization map
// with the predicate instead of keeping a second, divergent cache — seedScope is
// the only such caller, since LearnEffectiveOrigin resolves the learned origin.
func scopeCheckerWith(seedURL string, scope string, allowPrivate bool, hc *hostChecker) (func(string) bool, error) {
	seed, err := url.Parse(seedURL)
	if err != nil {
		return nil, fmt.Errorf("parse seed URL: %w", err)
	}
	if seed.Host == "" {
		return nil, fmt.Errorf("seed URL has no host: %q", redactSeedURL(seedURL))
	}

	ssrfCheck := func(u *url.URL) bool {
		if allowPrivate {
			return true
		}
		return !hc.isPrivate(u.Hostname())
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

// seedScope is the crawl's scope predicate plus a one-shot widening to the origin the
// SEED URL actually resolved to after redirects.
//
// Why it exists: an operator who seeds http://example.com against a server that 302s
// to https://example.com (or apex → www) gets a crawl where Chrome follows the
// redirect and every CDP-captured request carries the POST-redirect origin. The
// same-origin predicate compares "scheme://host" exactly, so it rejected all of them
// and the run produced an empty capture with exit code 0 and no diagnostic.
//
// CONTAINMENT. Scope is an engagement containment control, so the widening is
// deliberately narrow and auditable:
//
//  1. Only the SEED's own navigation can widen scope. LearnEffectiveOrigin is called
//     from the visit of the entry whose frontier key EQUALS the seed's, and nowhere
//     else, so a redirect issued by an arbitrary page deeper in the crawl — which an
//     attacker-controlled page could trigger at will — never widens anything. The gate
//     is seed identity rather than depth 0 because resume breaks depth as a proxy:
//     resumeFrontier restores pending entries before the seed is pushed and honors the
//     Depth the artifact claims, so a crafted checkpoint could put a non-seed URL at
//     depth 0 ahead of the seed and pick which page learned the origin (LAB-4678,
//     SEC-BE-004).
//
//  2. It is one-shot and adds exactly ONE origin: the scheme://host the seed resolved
//     to. It is not a domain-level relaxation, and a second call (a resumed depth-0
//     entry, a retry) cannot add another origin.
//
//  3. The learned origin must be a HOST VARIANT of the seed: the same host, or the
//     seed's host with a leading "www." added or removed. That is exactly the set of
//     cases the widening exists for (http→https, apex→www) and nothing more. Scheme
//     and port may change, because http→https is itself a port change and a different
//     port on the same host crosses no host boundary.
//
//     Bounding on the host rather than the REGISTRABLE DOMAIN is what keeps the
//     widening inside --scope same-origin, whose predicate is an exact scheme://host
//     comparison. A domain bound admits an origin the operator excluded — seed
//     https://www.target.com redirecting to https://staging-abc.target.com, via an
//     open redirect, a subdomain takeover or a misconfigured vhost — and operator
//     --header values are applied per page with no origin check, so a static
//     Authorization header goes with it (LAB-4678, SEC-BE-009). Under --scope
//     same-domain the narrow bound costs nothing, because the base predicate already
//     accepts every host under the registrable domain;
//     TestSeedScope_NarrowingDoesNotAffectSameDomainScope pins that.
//
//     An IdP hand-off, an open redirect on the seed, any other foreign-domain target,
//     and a sibling subdomain are all refused. Both refusals are reported with the
//     remedy: re-seed at the resolved URL, which admits exactly the one origin the
//     operator chose, rather than --scope same-domain, which would admit every
//     subdomain.
//
//  4. The SSRF gate still applies. A seed that redirects to 127.0.0.1,
//     169.254.169.254, or any RFC1918 address is refused unless the operator passed
//     --dangerous-allow-private, exactly as for the seed itself. The verdict is taken
//     once, at learn time, not per URL.
//
//  5. The widening is announced on stderr, so the operator sees the effective scope of
//     the run instead of silently getting a wider crawl.
//
// Headless backend only. On the net/http backend redirectScopeGuard rejects the
// cross-origin redirect during the seed fetch and reports it on stderr, so that path
// is loud rather than silent; widening it would mean letting a redirect through the
// guard before the guard has decided, which is a change to the control itself.
type seedScope struct {
	base         func(string) bool // policy predicate from scopeChecker (origin/domain match + SSRF)
	allowPrivate bool
	seedOrigin   string
	stderr       io.Writer

	// hosts is shared with the base predicate so a hostname resolved by either is
	// resolved once for the whole crawl.
	hosts *hostChecker

	mu        sync.RWMutex
	learned   bool   // LearnEffectiveOrigin already ran (one-shot)
	effOrigin string // the seed's post-redirect origin, "" when it matched seedOrigin
}

// newSeedScope builds the scope predicate for a crawl of seedURL. It wraps
// [scopeChecker] with the seed-effective-origin widening documented on
// [seedScope]. stderr may be nil to suppress the widening notice.
func newSeedScope(seedURL, scope string, allowPrivate bool, stderr io.Writer) (*seedScope, error) {
	hosts := newHostChecker()
	base, err := scopeCheckerWith(seedURL, scope, allowPrivate, hosts)
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
		hosts:        hosts,
	}, nil
}

// Check reports whether rawURL is in scope: either the configured policy accepts it,
// or it is on the seed's learned effective origin, which cleared the domain and SSRF
// gates once at learn time.
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
	// A plain string comparison: the effective origin already cleared the domain and
	// private-host gates in LearnEffectiveOrigin, and it is a single fixed host whose
	// verdict cannot change within a run. Re-running isPrivateHost here would re-do an
	// unbounded, uncached net.LookupHost on the per-captured-request scope hot path,
	// and s.base has already paid for one lookup before returning false.
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
	// holding the exclusive lock across it blocks every concurrent Check for the whole
	// resolution. The learned flag already guarantees only one caller gets past here,
	// so the checks need no lock — it is only reacquired to publish the result.
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
	// Host-variant bound: same host, or the seed's host ± a leading "www.". See
	// [seedScope]'s host-variant bound for why it is the host and not the registrable
	// domain.
	if !s.sameHostVariant(u.Hostname()) {
		if s.stderr != nil {
			// Two messages, because they are different operator situations: a foreign
			// domain is usually an IdP hand-off or an open redirect, while a sibling
			// host under the same domain is usually the real app on another subdomain.
			what := "a different domain than"
			if s.sameRegistrableDomain(u.Hostname()) {
				what = "a different host on the same domain as"
			}
			// Recommend RE-SEEDING rather than --scope same-domain. Re-seeding admits
			// exactly the one origin the operator chose; widening the scope admits
			// every subdomain, which is broader than what was just refused.
			fmt.Fprintf(s.stderr, "scope: seed redirected to %s, %s %s; not adding it to scope. "+ //nolint:errcheck // best-effort status
				"If that origin is the intended target, re-run with it as the seed URL\n",
				origin, what, s.seedOrigin)
		}
		return
	}
	// The SSRF decision is taken before publishing the origin so the operator is
	// never told the scope widened to a host the crawl will then refuse.
	if !s.allowPrivate && s.hosts.isPrivate(u.Hostname()) {
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

// seedHostname returns the seed's hostname, read from seedOrigin rather than stored
// separately so there is one source of truth for what the seed was.
func (s *seedScope) seedHostname() string {
	if u := parseHTTPURL(s.seedOrigin); u != nil {
		return u.Hostname()
	}
	return ""
}

// sameHostVariant reports whether host is the seed's own host, or the seed's host with
// a leading "www." added or removed. That is the bound on how far the seed-redirect
// widening may reach: exactly the two cases doc.go documents it for, http→https (same
// host, scheme change) and apex→www.
//
// Both directions of the www swap are accepted. doc.go names "apex -> www", but the
// reverse redirect is just as common a deployment and is the same one-label
// relationship; refusing it would be an arbitrary asymmetry.
//
// An IP-literal or single-label seed (http://127.0.0.1:8080, http://localhost) is
// handled by the exact-match arm, which permits the scheme-only case while refusing
// to treat one bare host as equivalent to any other.
func (s *seedScope) sameHostVariant(host string) bool {
	seedHost := s.seedHostname()
	if seedHost == "" || host == "" {
		return false
	}
	if strings.EqualFold(seedHost, host) {
		return true
	}
	const www = "www."
	// Exactly one leading "www." apart, in either direction.
	return strings.EqualFold(strings.TrimPrefix(strings.ToLower(seedHost), www), host) &&
		strings.HasPrefix(strings.ToLower(seedHost), www) ||
		strings.EqualFold(seedHost, strings.TrimPrefix(strings.ToLower(host), www)) &&
			strings.HasPrefix(strings.ToLower(host), www)
}

// sameRegistrableDomain reports whether host shares the seed's registrable domain.
//
// It is NOT the widening gate — sameHostVariant is, see [seedScope]'s host-variant
// bound. It is a diagnostic classifier, to tell the operator whether a refused redirect
// went to a foreign domain (usually an IdP hand-off or an open redirect) or to a
// sibling host on their own domain (usually the real app on another subdomain). Those
// are different situations and deserve different messages.
//
// It falls back to an exact hostname match when either side has no registrable
// domain — an IP-literal or single-label seed such as http://127.0.0.1:8080 or
// http://localhost.
func (s *seedScope) sameRegistrableDomain(host string) bool {
	seedHost := s.seedHostname()
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

// parseHTTPURL returns nil for invalid or non-HTTP(S) URLs.
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

// registeredDomain returns the eTLD+1: "api.example.com" -> "example.com".
func registeredDomain(host string) (string, error) {
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", err
	}
	return domain, nil
}

// ssrfSafeDialContext re-resolves at dial time, closing the DNS-rebinding TOCTOU
// window: a short-TTL domain can pass the upfront scope check as a public IP and
// resolve to 127.0.0.1 by the time client.Do dials. Delegates to
// pkg/ssrf.SafeDialContext, shared with pkg/probe.
func ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return ssrf.SafeDialContext(ctx, network, addr)
}

// seenKey returns the frontier's DEDUP key for rawURL: the canonicalized URL with its
// query string intact. Two links differing only in query string get different keys and
// are therefore separate pages ([urlFrontier.Push], [urlFrontier.Restore],
// [urlFrontier.Snapshot]). It is also the seed's identity for effective-origin
// learning (rodEngine.seedKey).
//
// Named rather than inlined because it and [frontierKey] differ only in one bool
// argument to canonicalizeURL: a caller that reaches for the wrong one still passes
// every fixture whose URLs carry no query, the case in which the two agree.
func seenKey(rawURL string) string {
	return canonicalizeURL(rawURL, false)
}

// frontierKey returns the PER-PATH key for rawURL: the canonicalized URL with its
// query string removed. It is NOT the dedup key — see [seenKey] — and is used for
// exactly one thing: counting how many query variants of a single path the frontier
// has admitted, bounded by [maxQueryVariantsPerPath], whose doc comment carries the
// reasoning for capping rather than collapsing variants.
func frontierKey(rawURL string) string {
	return canonicalizeURL(rawURL, true)
}

// canonicalizeURL lowercases scheme and host, strips the fragment and any default
// port, and — when stripQuery is set — removes the query string. "" on a parse error.
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

	// Or example.com and example.com:443 dedup as different URLs.
	hostname := u.Hostname()
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		u.Host = hostname
	}

	return u.String()
}
