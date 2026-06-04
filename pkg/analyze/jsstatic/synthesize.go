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

	var bundleBase *url.URL
	if captureURL != "" {
		if parsed, err := url.Parse(captureURL); err == nil {
			bundleBase = parsed
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
		// against PageURL first (document-relative paths), falling back to the
		// bundle URL when PageURL is empty or unparseable.
		base := bundleBase
		if ep.PageURL != "" {
			if pageBase, err := url.Parse(ep.PageURL); err == nil && pageBase.Host != "" {
				base = pageBase
			}
		}
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

// synthBody marshals a map of field-name → nil into a JSON object byte slice.
// Returns nil when fields is empty.
//
// Output is deterministic: encoding/json marshals map[string]interface{} with
// keys in sorted order, which is guaranteed by the Go specification ("The map
// keys are sorted and used as JSON object keys" —
// https://pkg.go.dev/encoding/json#Marshal). This guarantee holds regardless
// of the order of the input fields slice. In practice the current callers
// (collectObjectKeys) already return fields in sorted order, but that is a
// caller-side convention, not a correctness requirement here.
func synthBody(fields []string) []byte {
	if len(fields) == 0 {
		return nil
	}
	obj := make(map[string]interface{}, len(fields))
	for _, f := range fields {
		obj[f] = nil
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	return b
}
