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

package classify

import (
	"net/url"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// APIClassifier determines if a request is an API call.
type APIClassifier interface {
	// Name returns the classifier name (e.g., "rest", "graphql").
	Name() string

	// Classify returns whether the request is an API call and the confidence score.
	Classify(req crawl.ObservedRequest) (bool, float64)
}

// DetailedClassifier extends classification with a reason string.
type DetailedClassifier interface {
	APIClassifier
	// ClassifyDetail returns classification result with a reason string.
	ClassifyDetail(req crawl.ObservedRequest) (bool, float64, string)
}

// RunClassifiers applies all classifiers to requests and returns classified results.
func RunClassifiers(classifiers []APIClassifier, requests []crawl.ObservedRequest, threshold float64) []ClassifiedRequest {
	var results []ClassifiedRequest

	for _, req := range requests {
		var bestMatch ClassifiedRequest
		bestMatch.ObservedRequest = req
		bestMatch.IsAPI = false
		bestMatch.Confidence = 0

		// Capture per-observation multi-value-ness BEFORE Deduplicate can
		// merge values across observations and obscure which keys were
		// truly multi-value in any single request. Always non-nil so
		// downstream consumers can distinguish "RunClassifiers ran, no
		// multi-value keys" from "ClassifiedRequest built directly".
		bestMatch.MultiValueQueryKeys = make(map[string]bool)
		for k, vs := range req.QueryParams {
			if len(vs) > 1 {
				bestMatch.MultiValueQueryKeys[k] = true
			}
		}

		for _, classifier := range classifiers {
			var isAPI bool
			var confidence float64
			var reason string

			if dc, ok := classifier.(DetailedClassifier); ok {
				isAPI, confidence, reason = dc.ClassifyDetail(req)
			} else {
				isAPI, confidence = classifier.Classify(req)
				reason = "classified by " + classifier.Name()
			}

			if isAPI && confidence > bestMatch.Confidence {
				bestMatch.IsAPI = true
				bestMatch.Confidence = confidence
				bestMatch.APIType = classifier.Name()
				bestMatch.Reason = reason
			}
		}

		if bestMatch.Confidence >= threshold {
			results = append(results, bestMatch)
		}
	}

	return results
}

// Deduplicate removes duplicate classified requests, keeping the highest confidence.
// The deduplication key is METHOD:path (query params and fragments stripped).
// Multi-value QueryParams from duplicate observations are merged with union-of-values,
// preserving first-seen order.
//
// Memory usage: The map and order slice grow linearly with unique METHOD:path keys.
// In practice this is bounded by the upstream crawl layer's MaxPages setting
// (default 100). The import path (ReadCapture) does not enforce size limits,
// so callers importing from untrusted capture files should validate input size.
func Deduplicate(classified []ClassifiedRequest) []ClassifiedRequest {
	type entry struct {
		req ClassifiedRequest
	}
	seen := make(map[string]*entry)
	var order []string

	for _, req := range classified {
		parsedURL, err := url.Parse(req.URL)
		if err != nil {
			// Unparseable URLs: use raw URL as key.
			key := req.Method + ":" + req.URL
			if _, found := seen[key]; !found {
				order = append(order, key)
				seen[key] = &entry{req: req}
			}
			continue
		}

		// Dedup key intentionally omits host: the crawl layer's scope
		// restrictions (same-origin / same-domain) make cross-host
		// duplicates unlikely, and consolidating by path is the desired
		// behavior for single-target scans.
		key := req.Method + ":" + parsedURL.Path

		// For SOAP endpoints, include SOAPAction in the dedup key so distinct
		// operations on the same URL path are preserved.
		if sa := getSoapAction(req.Headers); sa != "" {
			key += ":" + sa
		}

		existing, found := seen[key]
		if !found {
			order = append(order, key)
			// Deep-copy QueryParams so that merging into the entry does not mutate
			// the caller's original ClassifiedRequest slices.
			entryCopy := req
			if req.QueryParams != nil {
				entryCopy.QueryParams = make(map[string][]string, len(req.QueryParams))
				for k, vs := range req.QueryParams {
					copied := make([]string, len(vs))
					copy(copied, vs)
					entryCopy.QueryParams[k] = copied
				}
			}
			entryCopy.MultiValueQueryKeys = mergeMultiValueKeys(nil, req.MultiValueQueryKeys)
			seen[key] = &entry{req: entryCopy}
		} else {
			// Merge multi-value QueryParams: union per key, preserving first-seen order.
			if req.QueryParams != nil {
				if existing.req.QueryParams == nil {
					existing.req.QueryParams = make(map[string][]string)
				}
				for k, vs := range req.QueryParams {
					existing.req.QueryParams[k] = MergeUniqueOrdered(existing.req.QueryParams[k], vs)
				}
			}

			// Union MultiValueQueryKeys: a key is multi-value in the
			// dedup entry if ANY contributing observation saw it as
			// multi-value. (Scalar values that merely differ across
			// observations do NOT make the merged entry multi-value —
			// that's the regression this tracking exists to prevent.)
			existing.req.MultiValueQueryKeys = mergeMultiValueKeys(existing.req.MultiValueQueryKeys, req.MultiValueQueryKeys)

			// Keep highest confidence, but preserve first occurrence's body/response.
			if req.Confidence > existing.req.Confidence {
				existing.req.Confidence = req.Confidence
				existing.req.Reason = req.Reason
				existing.req.APIType = req.APIType
			}
		}
	}

	results := make([]ClassifiedRequest, 0, len(order))
	for _, key := range order {
		results = append(results, seen[key].req)
	}
	return results
}

// MergeUniqueOrdered returns a new slice containing the values of a followed
// by the values of b, with duplicates removed. The first occurrence of each
// distinct value wins, preserving order. Neither input slice is modified.
//
// This function is safe to call when a or b reference data that should not be
// mutated (e.g., observation data passed to Deduplicate) — the returned slice
// is always a fresh allocation.
//
// Returns nil when both inputs are empty (treats nil and empty slices
// interchangeably) so callers can range over the result without a nil-check.
func MergeUniqueOrdered(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make([]string, 0, len(a)+len(b))
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, v := range a {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range b {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// mergeMultiValueKeys returns dst with each true entry from src added.
// If src is nil, dst is returned unchanged. If dst is nil and src is
// non-nil, a fresh map sized to src is allocated. Used by Deduplicate to
// union per-observation multi-value-key tracking across merged requests.
func mergeMultiValueKeys(dst, src map[string]bool) map[string]bool {
	if src == nil {
		return dst
	}
	if dst == nil {
		dst = make(map[string]bool, len(src))
	}
	for k, v := range src {
		if v {
			dst[k] = true
		}
	}
	return dst
}

// getSoapAction returns the SOAPAction header value, performing a case-insensitive lookup.
func getSoapAction(headers map[string]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "soapaction") {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}
