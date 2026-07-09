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
	"regexp"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/mediatype"
)

// Confidence scores for gRPC classification signals.
const (
	GRPCContentTypeConfidence        = 0.95 // Content-Type: application/grpc*
	GRPCTrailerConfidence            = 0.80 // grpc-status or grpc-message response header
	GRPCPathConfidence               = 0.60 // POST + /<pkg.Service>/<Method> path shape
	GRPCContentTypeTrailerConfidence = 0.99 // gRPC content-type AND trailer (HTTP/2-style)
)

// Reflection descriptor caps shared by the probe (live reflection walk)
// and generator (offline capture) paths so both bound descriptor memory
// identically. Enforcement lives in pkg/probe (walkFileDescriptors) and
// pkg/generate/grpc (Generate); this is the single source of truth for the
// values so retuning one place updates both.
const (
	MaxGRPCFileDescriptors = 1000
	MaxGRPCDescriptorBytes = 64 << 20 // 64 MiB
)

// grpcPathRE matches the gRPC convention /<pkg.qualified.Service>/<MethodName>.
// Anchored: a single slash-separated pair only. The package part starts with a
// letter and may contain dots; the method part starts with an uppercase letter
// per protobuf style.
var grpcPathRE = regexp.MustCompile(`^/[A-Za-z][\w.]*/[A-Z]\w*$`)

// GRPCClassifier classifies gRPC API requests using ordered heuristic rules.
type GRPCClassifier struct{}

// Name returns the classifier name.
func (c *GRPCClassifier) Name() string {
	return "grpc"
}

// Classify determines if the request is a gRPC API call.
func (c *GRPCClassifier) Classify(req crawl.ObservedRequest) (bool, float64) {
	isAPI, confidence, _ := c.ClassifyDetail(req)
	return isAPI, confidence
}

// ClassifyDetail returns classification result with a detailed reason string.
//
// Signals (each contributes a "+"-joined token to the reason):
//  1. Content-Type starts with application/grpc (request, else response) → 0.95 alone
//  2. Response headers contain grpc-status or grpc-message → 0.80 alone
//  3. POST method AND URL path matches /<pkg.Service>/<Method> → 0.60 alone
//
// When signals 1 AND 2 both fire, the confidence is bumped to 0.99 — gRPC
// content-type + gRPC trailers together are the "HTTP/2 + trailers"
// fingerprint from the gRPC-over-HTTP/2 spec (`application/grpc` requires
// HTTP/2). Other combinations take the max of firing signals' base
// confidences, with the reason string showing every signal that contributed.
func (c *GRPCClassifier) ClassifyDetail(req crawl.ObservedRequest) (bool, float64, string) {
	var signals []string

	hasContentType := false
	if hasGRPCContentType(getContentType(req.Headers)) {
		signals = append(signals, "grpc-content-type")
		hasContentType = true
	} else if hasGRPCContentType(req.Response.ContentType) {
		signals = append(signals, "grpc-response-content-type")
		hasContentType = true
	}

	hasTrailer := hasGRPCTrailerHeader(req.Response.Headers)
	if hasTrailer {
		signals = append(signals, "grpc-trailer-header")
	}

	hasPath := false
	if strings.EqualFold(req.Method, "POST") {
		// A malformed URL just skips the path-shape heuristic (fail-open, no
		// confidence penalty) — content-type/trailer signals still apply.
		if parsed, err := url.Parse(req.URL); err == nil && grpcPathRE.MatchString(parsed.Path) {
			signals = append(signals, "grpc-path-shape")
			hasPath = true
		}
	}

	if len(signals) == 0 {
		return false, 0, ""
	}

	var confidence float64
	switch {
	case hasContentType && hasTrailer:
		confidence = GRPCContentTypeTrailerConfidence
	case hasContentType:
		confidence = GRPCContentTypeConfidence
	case hasTrailer:
		confidence = GRPCTrailerConfidence
	case hasPath:
		confidence = GRPCPathConfidence
	default:
		// Unreachable today: the len(signals)==0 guard above guarantees at
		// least one of hasContentType/hasTrailer/hasPath is set. Kept as a
		// safety floor so a future signal added without its own case can't
		// silently return (true, 0.0) — it defaults to the lowest positive
		// confidence instead of a filtered-out zero.
		confidence = GRPCPathConfidence
	}

	return true, confidence, strings.Join(signals, "+")
}

// hasGRPCContentType reports whether ct is a gRPC content type
// (application/grpc, application/grpc+proto, application/grpc+json,
// application/grpc-web, application/grpc-web+proto, ...).
func hasGRPCContentType(ct string) bool {
	return strings.HasPrefix(mediatype.Base(ct), "application/grpc")
}

// hasGRPCTrailerHeader reports whether headers contain grpc-status or
// grpc-message (case-insensitive). These are gRPC's trailer convention; on
// HTTP/1.x or proxy-flattened captures they appear as regular headers.
func hasGRPCTrailerHeader(headers map[string]string) bool {
	for k := range headers {
		if strings.EqualFold(k, "grpc-status") || strings.EqualFold(k, "grpc-message") {
			return true
		}
	}
	return false
}
