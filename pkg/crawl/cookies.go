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
	"sort"
	"strings"

	"github.com/go-rod/rod/lib/proto"
)

// ExtractCookieHeader removes Cookie headers (case-insensitive) from the map
// and returns the cookie value separately. If multiple Cookie headers exist
// with different casings, they are concatenated with "; ".
func ExtractCookieHeader(headers map[string]string) (cookieValue string, remaining map[string]string) {
	remaining = make(map[string]string, len(headers))
	var cookieParts []string
	// Iterate in sorted key order so concatenation of differently-cased
	// "Cookie" headers is deterministic across runs (Go map iteration is
	// randomized). Matters for duplicate cookie precedence.
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := headers[k]
		if strings.EqualFold(k, "Cookie") {
			cookieParts = append(cookieParts, v)
		} else {
			remaining[k] = v
		}
	}
	return strings.Join(cookieParts, "; "), remaining
}

// ParseCookiesToParams parses an HTTP Cookie header value into Chrome DevTools
// Protocol NetworkCookieParam entries for injection into Chrome's cookie store.
// The Cookie header format is "name=value; name2=value2". The targetURL provides
// the domain and scheme for the generated cookie parameters.
func ParseCookiesToParams(targetURL, cookieValue string) ([]*proto.NetworkCookieParam, error) {
	if cookieValue == "" {
		return nil, nil
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parse target URL for cookies: %w", err)
	}
	// url.Parse accepts bare hostnames and scheme-only strings without
	// erroring. Reject anything that isn't an absolute http(s) URL so we
	// don't emit cookies with an empty Host (which Chrome would drop
	// silently, causing LAB-2222 to regress without any signal).
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid target URL for cookies %q: must be an absolute http(s) URL", targetURL)
	}

	var params []*proto.NetworkCookieParam
	for _, pair := range strings.Split(cookieValue, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		value := ""
		if len(parts) == 2 {
			value = strings.TrimSpace(parts[1])
		}

		params = append(params, &proto.NetworkCookieParam{
			Name:  name,
			Value: value,
			// Path is "/" regardless of the target URL's path so session cookies
			// apply to all endpoints on the host, matching standard session-cookie
			// behavior.
			Path:   "/",
			Secure: u.Scheme == "https",
			// HttpOnly is deliberately omitted so apps that read auth state via
			// JS document.cookie continue to work. HttpOnly does not affect
			// outbound request cookie attachment — it only restricts JS reads.
			//
			// Setting URL (and omitting Domain) produces a host-only cookie
			// scoped to the exact hostname — subdomain redirects won't carry
			// these cookies. This is the correct scope for LAB-2222's
			// session-cookie propagation. Passing both Domain and URL is
			// redundant: Chrome derives Domain from URL when Domain is unset.
			URL: u.Scheme + "://" + u.Host,
		})
	}

	return params, nil
}

// CookieInjector installs cookies into a browser's cookie store. The
// production implementation is BrowserManager.SetCookies; tests pass a
// spy. The signature mirrors rod.Browser.SetCookies so production
// callers can pass it as a method value (browserMgr.SetCookies).
type CookieInjector func(cookies []*proto.NetworkCookieParam) error

// ApplyCookieHeader is the full pipeline behind the LAB-2222 fix:
// (1) strip Cookie from headers via ExtractCookieHeader,
// (2) parse the cookie value into NetworkCookieParams,
// (3) install them via inject (typically BrowserManager.SetCookies).
// It returns the header map with Cookie removed so the caller can pass
// it to the engine as extra HTTP headers without double-injecting the
// cookie (which would land in Network.setExtraHTTPHeaders and get
// stripped by Spring Security-style redirects — the original bug).
//
// When headers contains no Cookie entry, inject is NOT called and the
// headers map is returned with Cookie removal applied idempotently.
// Parse and inject errors are wrapped with "parse cookies:" and
// "inject cookies:" respectively — operators rely on these prefixes.
func ApplyCookieHeader(headers map[string]string, targetURL string, inject CookieInjector) (map[string]string, error) {
	cookieValue, extraHeaders := ExtractCookieHeader(headers)
	if cookieValue == "" {
		return extraHeaders, nil
	}
	params, err := ParseCookiesToParams(targetURL, cookieValue)
	if err != nil {
		return nil, fmt.Errorf("parse cookies: %w", err)
	}
	if err := inject(params); err != nil {
		return nil, fmt.Errorf("inject cookies: %w", err)
	}
	return extraHeaders, nil
}
