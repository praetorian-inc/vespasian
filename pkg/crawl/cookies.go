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
	"strings"

	"github.com/go-rod/rod/lib/proto"
)

// ExtractCookieHeader removes Cookie headers (case-insensitive) from the map
// and returns the cookie value separately. If multiple Cookie headers exist
// with different casings, they are concatenated with "; ".
func ExtractCookieHeader(headers map[string]string) (cookieValue string, remaining map[string]string) {
	remaining = make(map[string]string, len(headers))
	var cookieParts []string
	for k, v := range headers {
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
			// Domain is set to the exact hostname (no leading dot), producing a
			// host-only cookie. Subdomain redirects will not carry these cookies.
			// This is correct for LAB-2222's session-cookie scope.
			Domain: u.Hostname(),
			// Path is "/" regardless of the target URL's path so session cookies
			// apply to all endpoints on the host, matching standard session-cookie
			// behavior.
			Path:   "/",
			Secure: u.Scheme == "https",
			// HttpOnly is deliberately omitted so apps that read auth state via
			// JS document.cookie continue to work. HttpOnly does not affect
			// outbound request cookie attachment — it only restricts JS reads.
			URL: u.Scheme + "://" + u.Host,
		})
	}

	return params, nil
}
