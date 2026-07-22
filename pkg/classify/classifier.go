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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"mime"
	"net/url"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/mediatype"
)

// DefaultConfidenceThreshold is the default minimum confidence for a request to
// be classified as an API. It is single-sourced here and referenced by the SDK
// and CLI defaults so the threshold is documented rather than a bare literal
// scattered across entry points (LAB-4678).
const DefaultConfidenceThreshold = 0.5

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
func Deduplicate(classified []ClassifiedRequest) []ClassifiedRequest { //nolint:gocyclo // boundary normalization for multipart adds necessary branches
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

		// If this observation has a body, include the base content type and a
		// short hash of the body bytes in the key so that:
		//   - Distinct body shapes on the same path+method survive as separate
		//     entries (required for downstream form/JSON field-merge logic in
		//     buildOperation in pkg/generate/rest/openapi.go, which unions fields
		//     across observations).
		//   - Identical bodies still collapse correctly (true duplicates).
		//   - Empty-body requests (GET, DELETE, HEAD, OPTIONS) are unaffected.
		if len(req.Body) > 0 {
			ct := getContentType(req.Headers)
			if ct != "" {
				key += ":" + mediatype.Base(ct)
			}
			// Append a short fingerprint of the body so distinct payload shapes
			// on the same endpoint+method+CT survive deduplication. This is
			// required for downstream form/JSON merge logic in buildOperation
			// to see all observations and union their fields. 8 bytes (64 bits)
			// is a deliberate balance: birthday-collision probability is ~1e-14
			// at 500 distinct bodies per endpoint, well under realistic crawl
			// scale (capped at MaxPages, default 100). With 1M distinct bodies the
			// probability rises to ~5e-8, still negligible in practice.
			// A collision would silently merge two distinct bodies into one dedup
			// bucket; this is no worse than pre-fix behavior and worth the simpler key.
			fingerprintBody := req.Body
			if ct != "" {
				if mt, params, err := mime.ParseMediaType(ct); err == nil && mt == "multipart/form-data" {
					if boundary := params["boundary"]; len(boundary) >= 4 {
						// Multipart bodies contain a random boundary token (per-request) that
						// would otherwise make every observation unique. Normalize it to a
						// sentinel so identical logical forms with different boundaries dedup.
						// boundary < 4 chars: skip normalization, fall through to raw body hash.
						// This is defensive — RFC 2046 allows 1-70 char boundaries but real-world
						// browsers/libraries use 30+ chars. A pathologically short boundary would
						// corrupt the body more than it'd help dedup.
						fingerprintBody = bytes.ReplaceAll(req.Body, []byte(boundary), []byte("BOUNDARY"))
					}
				}
			}
			h := sha256.Sum256(fingerprintBody)
			key += ":" + hex.EncodeToString(h[:8])
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

			// Keep highest confidence. Confidence/reason selection is
			// independent of response selection below: whether the endpoint is
			// an API (confidence) and which captured response documents it are
			// orthogonal concerns, and both are chosen order-independently so a
			// fixed capture yields the same result regardless of the order in
			// which duplicate observations were captured.
			//
			// On equal confidence, break the tie deterministically on
			// (APIType, Reason). Two observations of the same endpoint can reach
			// the same confidence via different signals (e.g. a POST on /api/x
			// scores 0.7 from the method rule whether or not a request-side
			// signal also fired), so without a tie-break the retained
			// Reason/APIType would depend on the nondeterministic observation
			// order and the -v explanation would vary run-to-run (Gemini
			// review). The lexicographically greater (APIType, Reason) pair wins.
			better := req.Confidence > existing.req.Confidence
			if !better && req.Confidence == existing.req.Confidence {
				if req.APIType != existing.req.APIType {
					better = req.APIType > existing.req.APIType
				} else {
					better = req.Reason > existing.req.Reason
				}
			}
			if better {
				existing.req.Confidence = req.Confidence
				existing.req.Reason = req.Reason
				existing.req.APIType = req.APIType
			}

			// Select the retained response deterministically (LAB-4678, A4).
			// Previously the first-seen observation's response was kept, but the
			// input order is the crawl's capture order — a nondeterministic Go
			// map iteration (pkg/crawl/network.go Results()) — so the documented
			// response schema could differ run-to-run even when the endpoint set
			// was identical. preferredResponse is order-free: it prefers a
			// populated response over an empty (half-captured) one and breaks
			// ties on a stable content fingerprint.
			existing.req.Response = preferredResponse(existing.req.Response, req.Response)
		}
	}

	results := make([]ClassifiedRequest, 0, len(order))
	for _, key := range order {
		results = append(results, seen[key].req)
	}
	return results
}

// responsePopulated reports whether an observed response carries usable content.
// A half-captured response (the request was recorded on NetworkRequestWillBeSent
// but its NetworkLoadingFinished had not fired when the crawl read results) has
// a zero status and empty content-type/body; such a response documents nothing.
//
// A positive StatusCode alone is sufficient: a completed bodyless response
// (e.g. a DELETE returning 204 No Content, or a 304) legitimately has no body
// or content-type, yet it documents the endpoint's real status. Requiring a
// body/content-type here would treat such a response as unpopulated and let the
// fingerprint tie-break in preferredResponse retain a zero-status placeholder
// instead, after which OpenAPI generation defaults the missing status to 200 —
// documenting the wrong status code (Codex review).
func responsePopulated(r crawl.ObservedResponse) bool {
	return r.StatusCode > 0 || len(r.Body) > 0 || r.ContentType != ""
}

// responseFingerprint returns a stable content hash of a response over its
// status, content-type, and body. It is used only as an order-independent
// tie-break in preferredResponse; the field separators keep distinct splits
// from colliding.
func responseFingerprint(r crawl.ObservedResponse) [sha256.Size]byte {
	h := sha256.New()
	var status [8]byte
	binary.BigEndian.PutUint64(status[:], uint64(r.StatusCode)) // #nosec G115 -- status is a small non-negative HTTP code; wrap is irrelevant to a hash key
	h.Write(status[:])
	h.Write([]byte{0})
	h.Write([]byte(r.ContentType))
	h.Write([]byte{0})
	h.Write(r.Body)
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// preferredResponse deterministically selects which of two responses observed
// for the same deduplicated endpoint should be retained. Selection is
// independent of argument order so a fixed capture yields the same documented
// response regardless of the (nondeterministic) order in which the crawl
// captured the duplicate observations (LAB-4678, A4):
//  1. A populated response beats an unpopulated (half-captured) one — a real
//     response documents the endpoint better than an empty placeholder.
//  2. When both are populated (or both empty), the response with the smaller
//     content fingerprint wins, an order-free tie-break.
func preferredResponse(a, b crawl.ObservedResponse) crawl.ObservedResponse {
	ap, bp := responsePopulated(a), responsePopulated(b)
	if ap != bp {
		if bp {
			return b
		}
		return a
	}
	fa, fb := responseFingerprint(a), responseFingerprint(b)
	if bytes.Compare(fb[:], fa[:]) < 0 {
		return b
	}
	return a
}

// MergeUniqueOrdered returns a new slice containing the values of a followed
// by the values of b, with duplicates removed. The first occurrence of each
// distinct value wins, preserving order. Neither input slice is modified.
//
// This function is safe to call when a or b reference data that should not be
// mutated (e.g., observation data passed to Deduplicate) — the returned slice
// is always a fresh allocation.
//
// The output is capped at crawl.MaxQueryParamValues entries; duplicates are
// removed regardless of where they appear in a or b.
//
// Returns nil when both inputs are empty (treats nil and empty slices
// interchangeably) so callers can range over the result without a nil-check.
func MergeUniqueOrdered(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	limit := crawl.MaxQueryParamValues
	outCapacity := len(a) + len(b)
	if outCapacity > limit {
		outCapacity = limit
	}
	out := make([]string, 0, outCapacity)
	seen := make(map[string]struct{}, outCapacity)
	for _, v := range a {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
		if len(out) >= limit {
			return out
		}
	}
	for _, v := range b {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
		if len(out) >= limit {
			return out
		}
	}
	return out
}

// mergeMultiValueKeys returns dst with each true entry from src added.
// If src is nil, dst is returned unchanged. If dst is nil and src is
// non-nil, a fresh map sized to src is allocated. Used by Deduplicate to
// union per-observation multi-value-key tracking across merged requests.
//
// False-valued entries in src are intentionally omitted: consumers
// (notably buildOperation in pkg/generate/rest) treat map-absence as
// "not multi-value", matching Go's zero-value semantics for bool, so
// there is no need to record key=false explicitly.
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

// getHeader returns the value of the named header, matched case-insensitively.
// Returns "" if absent.
func getHeader(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// getContentType returns the Content-Type header value, case-insensitively.
func getContentType(headers map[string]string) string {
	return getHeader(headers, "content-type")
}
