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
// QueryParams from all duplicate observations are merged.
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
			seen[key] = &entry{req: req}
		} else {
			// Merge unique QueryParams.
			if req.QueryParams != nil {
				if existing.req.QueryParams == nil {
					existing.req.QueryParams = make(map[string]string)
				}
				for k, v := range req.QueryParams {
					if _, exists := existing.req.QueryParams[k]; !exists {
						existing.req.QueryParams[k] = v
					}
				}
			}

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

// getSoapAction returns the SOAPAction header value, performing a case-insensitive lookup.
func getSoapAction(headers map[string]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "soapaction") {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}
