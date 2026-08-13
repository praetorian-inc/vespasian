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

// GenericXMLConfidence is what a bare text/xml response scores for WSDL when no
// SOAP-specific signal is present. It sits below DefaultConfidenceThreshold, so
// generic XML alone is never a WSDL match, and therefore never a WSDL vote in
// pipeline.DetectAPIType.
//
// It was 0.85, the same as application/soap+xml. That is above RESTClassifier's
// ContentTypeConfidence of 0.8, because text/xml is also an exact apiContentTypes
// entry there. Under DetectAPIType's exclusive per-request vote the higher score
// wins the request outright, so a single text/xml response produced
// (rest=0, wsdl=1) and challengerWins returned true against a zero REST tally:
// one XML response typed an entire capture as SOAP and switched the generator
// from OpenAPI to WSDL. Measured before this change:
//
//	DetectAPIType([one text/xml response], 0.5) = "wsdl"
//	3 REST responses + 5 text/xml responses    = "wsdl"
//
// TestWSDL_GenericXMLIsNotASoapVote and TestDetectAPIType_GenericXMLDoesNotTypeTheCapture
// pin both halves.
const GenericXMLConfidence = 0.4

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
//  3. SOAP envelope in request or response body → confidence 0.90
//  4. ?wsdl query param or /wsdl path suffix → confidence 0.90
//  5. Content-type application/soap+xml → confidence 0.85
//  6. Content-type text/xml → confidence GenericXMLConfidence
//
// Signals 5 and 6 are split because the two media types carry different
// evidence. application/soap+xml is SOAP-specific, so it identifies the protocol
// on its own. text/xml is generic XML, shared by SOAP and by any REST endpoint
// that returns XML, so on its own it identifies nothing — see
// GenericXMLConfidence for what scoring the two alike cost.
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

	// Signal 2: SOAP envelope in the request OR the response body.
	//
	// The response side was added with the signal-6 split below. Lowering bare
	// text/xml means a genuine SOAP exchange can no longer coast on its
	// content-type alone, so the protocol has to be identifiable from something
	// SOAP-specific. An envelope in the response is exactly that, and it covers
	// the case the old scoring silently relied on: a SOAP service reached without
	// a SOAPAction header, whose request body this classifier never sees because
	// the capture recorded only the response.
	if hasSoapEnvelope(req.Body) || hasSoapEnvelope(req.Response.Body) {
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

	// Signals 5 and 6: content-type. Split because application/soap+xml is
	// SOAP-specific while text/xml is generic XML; see GenericXMLConfidence.
	ct := strings.ToLower(req.Response.ContentType)
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	switch ct {
	case "application/soap+xml":
		if confidence < 0.85 {
			confidence = 0.85
		}
		if reason == "" {
			reason = "soap-content-type"
		} else {
			reason += "+soap-content-type"
		}
	case "text/xml":
		// Signal 6: generic XML. Scored below DefaultConfidenceThreshold so it
		// cannot carry a WSDL verdict by itself; when a real SOAP signal is also
		// present the max above has already exceeded this.
		if confidence < GenericXMLConfidence {
			confidence = GenericXMLConfidence
		}
		if reason == "" {
			reason = "generic-xml-content-type"
		} else {
			reason += "+generic-xml-content-type"
		}
	}

	// Negative signal: RSS/Atom exclusion.
	// Only reduce confidence when a content-type signal is the SOLE signal.
	// Both content-type reasons are covered: after the signal-5/6 split a feed
	// served as text/xml reaches this with the generic-xml reason and 0.4, and
	// checking only the soap reason would have left this branch matching nothing
	// a feed actually produces.
	if reason == "soap-content-type" || reason == "generic-xml-content-type" {
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
