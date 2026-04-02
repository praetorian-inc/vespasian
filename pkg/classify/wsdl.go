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
	"net/url"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// WSDLClassifier classifies SOAP/WSDL API requests using ordered heuristic rules.
type WSDLClassifier struct{}

// Name returns the classifier name.
func (c *WSDLClassifier) Name() string {
	return "wsdl"
}

// Classify determines if the request is a SOAP/WSDL API call.
func (c *WSDLClassifier) Classify(req crawl.ObservedRequest) (bool, float64) {
	isAPI, confidence, _ := c.ClassifyDetail(req)
	return isAPI, confidence
}

// ClassifyDetail returns classification result with a detailed reason string.
//
// Signals applied in order, taking max confidence (not additive):
//  1. Static asset exclusion → (false, 0, "")
//  2. SOAPAction header present → confidence 0.95
//  3. SOAP envelope in request body → confidence 0.90
//  4. ?wsdl query param or /wsdl path suffix → confidence 0.90
//  5. Content-type text/xml or application/soap+xml → confidence 0.85
//
// Negative signal: RSS/Atom feeds reduce confidence to 0.3 when only
// the soap-content-type signal matched.
func (c *WSDLClassifier) ClassifyDetail(req crawl.ObservedRequest) (bool, float64, string) { //nolint:gocyclo // multi-signal heuristic classifier
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return false, 0, ""
	}

	lowerPath := strings.ToLower(parsedURL.Path)

	// Static asset exclusion.
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return false, 0, ""
		}
	}

	var confidence float64
	var reason string

	// Signal 1: SOAPAction header present (case-insensitive).
	if _, ok := getHeaderCaseInsensitive(req.Headers, "SOAPAction"); ok {
		confidence = 0.95
		reason = "soapaction-header"
	}

	// Signal 2: SOAP envelope in request body.
	if hasSoapEnvelope(req.Body) {
		if confidence < 0.90 {
			confidence = 0.90
		}
		if reason == "" {
			reason = "soap-envelope"
		} else {
			reason += "+soap-envelope"
		}
	}

	// Signal 3: ?wsdl query param or URL path ends with /wsdl (case-insensitive).
	lowerQuery := strings.ToLower(parsedURL.RawQuery)
	if strings.Contains(lowerQuery, "wsdl") || strings.HasSuffix(lowerPath, "/wsdl") {
		if confidence < 0.90 {
			confidence = 0.90
		}
		if reason == "" {
			reason = "wsdl-url"
		} else {
			reason += "+wsdl-url"
		}
	}

	// Signal 4: Content-type is text/xml or application/soap+xml.
	ct := strings.ToLower(req.Response.ContentType)
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	if ct == "text/xml" || ct == "application/soap+xml" {
		if confidence < 0.85 {
			confidence = 0.85
		}
		if reason == "" {
			reason = "soap-content-type"
		} else {
			reason += "+soap-content-type"
		}
	}

	// Negative signal: RSS/Atom exclusion.
	// Only reduce confidence when soap-content-type is the sole signal.
	if confidence == 0.85 && reason == "soap-content-type" {
		body := req.Response.Body
		if bytes.Contains(body, []byte("<rss")) ||
			bytes.Contains(body, []byte("<feed")) ||
			bytes.Contains(body, []byte("<channel")) {
			confidence = 0.3
		}
	}

	return confidence > 0, confidence, reason
}

// getHeaderCaseInsensitive looks up a header value using case-insensitive key matching.
func getHeaderCaseInsensitive(headers map[string]string, key string) (string, bool) {
	lowerKey := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == lowerKey {
			return v, true
		}
	}
	return "", false
}

// hasSoapEnvelope reports whether body contains a SOAP envelope marker.
func hasSoapEnvelope(body []byte) bool {
	return bytes.Contains(body, []byte("<soap:Envelope")) ||
		bytes.Contains(body, []byte("<SOAP-ENV:Envelope")) ||
		bytes.Contains(body, []byte("schemas.xmlsoap.org/soap/envelope"))
}
