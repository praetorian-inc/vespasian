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

package importer

import (
	"io"
	"net/url"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// ImportOptions configures filtering behavior for traffic import.
type ImportOptions struct {
	// Scope filters requests by domain (e.g., "example.com" or "*.example.com").
	// Empty scope matches all requests.
	Scope string
}

// matchesScope checks if a URL matches the given scope pattern.
// Supports exact domain matching and wildcard subdomain matching (*.example.com).
// Empty scope matches all URLs.
func matchesScope(urlStr, scope string) bool {
	if scope == "" {
		return true
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	host := parsed.Hostname()

	// Check for wildcard pattern
	if strings.HasPrefix(scope, "*.") {
		suffix := scope[2:] // Remove "*."
		// Match subdomains but not the root domain
		return strings.HasSuffix(host, "."+suffix)
	}

	// Exact match
	return host == scope
}

// ImportWithOptions imports traffic with filtering options applied.
func ImportWithOptions(importer TrafficImporter, r io.Reader, opts ImportOptions) ([]crawl.ObservedRequest, error) {
	requests, err := importer.Import(r)
	if err != nil {
		return nil, err
	}

	// If no scope specified, return all requests
	if opts.Scope == "" {
		return requests, nil
	}

	// Filter requests by scope
	var filtered []crawl.ObservedRequest
	for _, req := range requests {
		if matchesScope(req.URL, opts.Scope) {
			filtered = append(filtered, req)
		}
	}

	return filtered, nil
}
