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

// ExtractCookieHeader pulls Cookie headers out case-insensitively, joining
// multiple casings with "; ".
func ExtractCookieHeader(headers map[string]string) (cookieValue string, remaining map[string]string) {
	remaining = make(map[string]string, len(headers))
	var cookieParts []string
	// Sorted, because Go randomizes map iteration and duplicate cookie precedence
	// depends on the order.
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

// ParseCookiesToParams converts "name=value; name2=value2" into CDP cookie params
// scoped by targetURL. Errors unless targetURL is an absolute http(s) URL.
func ParseCookiesToParams(targetURL, cookieValue string) ([]*proto.NetworkCookieParam, error) {
	if cookieValue == "" {
		return nil, nil
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parse target URL for cookies: %w", err)
	}
	// url.Parse accepts bare hostnames without erroring, and a cookie with an empty
	// Host is dropped by Chrome silently — session propagation would just stop
	// working with no signal (LAB-2222).
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid target URL for cookies %q: must be an absolute http(s) URL", redactSeedURL(targetURL))
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
			// "/" regardless of the target path, so session cookies cover every
			// endpoint on the host.
			Path:   "/",
			Secure: u.Scheme == "https",
			// HttpOnly omitted so apps reading auth state via document.cookie still
			// work; it restricts JS reads only, never outbound attachment.
			//
			// URL without Domain makes a host-only cookie, so subdomain redirects do
			// not carry it. Chrome derives Domain from URL, so passing both is
			// redundant.
			URL: u.Scheme + "://" + u.Host,
		})
	}

	return params, nil
}

// CookieInjector mirrors rod.Browser.SetCookies so BrowserManager.SetCookies can
// be passed as a method value; tests pass a spy.
type CookieInjector func(cookies []*proto.NetworkCookieParam) error

// ApplyCookieHeader strips Cookie from headers, parses it, and installs it via
// inject (LAB-2222). It returns the map WITHOUT Cookie, which is what stops the
// caller double-injecting: a Cookie left in the extra-headers map goes out via
// Network.setExtraHTTPHeaders and is stripped by Spring Security-style redirects.
//
// No Cookie entry means inject is not called. Errors are wrapped "parse cookies:"
// and "inject cookies:"; operators rely on those prefixes.
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
