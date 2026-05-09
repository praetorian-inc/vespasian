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

package jsstatic

import (
	"encoding/json"
	"net/url"
	"sort"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// toRequests converts a slice of ExtractedEndpoint into crawl.ObservedRequest
// values. captureURL is the URL of the JS bundle that was analyzed; it is used
// to resolve relative endpoint URLs to absolute form.
//
// Rules:
//   - Source is taken directly from ExtractedEndpoint.SourceTag.
//   - If BodyFields is non-empty, a synthetic JSON body is constructed as
//     {"field": null, ...} with keys sorted lexicographically. This lets
//     pkg/generate/rest.InferSchema produce a real object schema.
//   - GET requests (and any method with zero BodyFields) receive a nil Body.
//   - Content-Type header is added when ExtractedEndpoint.ContentType is set.
//   - PageURL is propagated from ExtractedEndpoint.PageURL.
func toRequests(endpoints []ExtractedEndpoint, captureURL string) []crawl.ObservedRequest {
	if len(endpoints) == 0 {
		return nil
	}

	var base *url.URL
	if captureURL != "" {
		if parsed, err := url.Parse(captureURL); err == nil {
			base = parsed
		}
	}

	reqs := make([]crawl.ObservedRequest, 0, len(endpoints))
	for _, ep := range endpoints {
		req := crawl.ObservedRequest{
			Method:  ep.Method,
			Source:  ep.SourceTag,
			PageURL: ep.PageURL,
		}

		// Resolve URL: absolute URLs are preserved; relative URLs are resolved
		// against the bundle's origin URL.
		req.URL = resolveURL(ep.URL, base)

		// Synthesize JSON body when BodyFields are present.
		if len(ep.BodyFields) > 0 {
			req.Body = synthBody(ep.BodyFields)
		}

		// Add Content-Type header when set.
		if ep.ContentType != "" {
			req.Headers = map[string]string{"Content-Type": ep.ContentType}
		}

		reqs = append(reqs, req)
	}
	return reqs
}

// resolveURL resolves rawURL relative to base. If rawURL is already absolute
// or base is nil, rawURL is returned unchanged.
func resolveURL(rawURL string, base *url.URL) string {
	if base == nil {
		return rawURL
	}
	ref, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if ref.IsAbs() {
		return rawURL
	}
	return base.ResolveReference(ref).String()
}

// synthBody marshals a sorted map of field-name → nil into a JSON object byte
// slice. Returns nil when fields is empty.
func synthBody(fields []string) []byte {
	if len(fields) == 0 {
		return nil
	}
	// Sort for deterministic output.
	sorted := make([]string, len(fields))
	copy(sorted, fields)
	sort.Strings(sorted)

	// Build an ordered-key JSON object manually so the output is deterministic
	// regardless of Go map iteration order.
	obj := make(map[string]interface{}, len(sorted))
	for _, f := range sorted {
		obj[f] = nil
	}

	// json.Marshal on a map produces sorted keys in Go 1.12+.
	b, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	return b
}
