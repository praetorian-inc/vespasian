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

// toRequests converts endpoints to requests, resolving relative URLs against
// captureURL. BodyFields become a synthetic {"field": null} body so
// rest.InferSchema produces a real object schema; no fields means a nil body.
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

		// PageURL first for document-relative paths, then the bundle URL.
		base := bundleBase
		if ep.PageURL != "" {
			if pageBase, err := url.Parse(ep.PageURL); err == nil && pageBase.Host != "" {
				base = pageBase
			}
		}
		req.URL = resolveURL(ep.URL, base)

		if len(ep.BodyFields) > 0 {
			req.Body = synthBody(ep.BodyFields)
		}

		if ep.ContentType != "" {
			req.Headers = map[string]string{"Content-Type": ep.ContentType}
		}

		reqs = append(reqs, req)
	}
	return reqs
}

// resolveURL returns rawURL unchanged when it is absolute or base is nil.
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

// synthBody marshals field->nil into a JSON object; nil when fields is empty.
//
// Deterministic whatever order fields arrives in: encoding/json sorts map keys
// ("The map keys are sorted and used as JSON object keys" —
// https://pkg.go.dev/encoding/json#Marshal), so callers need not pre-sort.
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
