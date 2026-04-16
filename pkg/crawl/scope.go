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

	"golang.org/x/net/publicsuffix"
)

// scopeChecker returns a function that checks whether a URL is in scope
// relative to the seed URL, based on the scope policy.
//
// Scope policies:
//   - "same-origin": exact scheme + host + port match (equivalent to Katana's fqdn)
//   - "same-domain": registered domain match, allowing subdomains (equivalent to Katana's rdn)
func scopeChecker(seedURL string, scope string) (func(string) bool, error) {
	seed, err := url.Parse(seedURL)
	if err != nil {
		return nil, fmt.Errorf("parse seed URL: %w", err)
	}
	if seed.Host == "" {
		return nil, fmt.Errorf("seed URL has no host: %q", seedURL)
	}

	switch scope {
	case "same-domain":
		seedDomain, err := registeredDomain(seed.Hostname())
		if err != nil {
			return nil, fmt.Errorf("extract registered domain: %w", err)
		}
		return func(rawURL string) bool {
			u, err := url.Parse(rawURL)
			if err != nil || u.Host == "" {
				return false
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return false
			}
			d, err := registeredDomain(u.Hostname())
			if err != nil {
				return false
			}
			return strings.EqualFold(d, seedDomain)
		}, nil

	default: // "same-origin" and any unknown value
		seedOrigin := seed.Scheme + "://" + seed.Host
		return func(rawURL string) bool {
			u, err := url.Parse(rawURL)
			if err != nil || u.Host == "" {
				return false
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return false
			}
			return (u.Scheme + "://" + u.Host) == seedOrigin
		}, nil
	}
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

// normalizeURL strips the fragment and normalizes a URL for deduplication.
// It returns the empty string for unparseable URLs.
func normalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.Fragment = ""
	return u.String()
}
