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
	"slices"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/mediatype"
)

// staticExtensions lists file extensions that indicate static assets.
var staticExtensions = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".svg", ".map",
}

// staticPathSegments lists path segments that indicate static asset directories.
var staticPathSegments = []string{
	"/static/", "/assets/", "/dist/", "/bundle/",
}

// apiContentTypes lists exact content types that indicate API responses. It is
// the first matching tier only — matchAPIContentType also accepts any
// application/*+json or application/*+xml structured syntax suffix, so this list
// does not bound what classifies as an API media type.
var apiContentTypes = []string{
	"application/json", "application/xml", "text/xml", "application/problem+json",
	"application/vnd.api+json", "application/hal+json",
}

// apiPathSegments lists path segments that indicate API endpoints.
var apiPathSegments = []string{
	"/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/rpc/", "/graphql",
}

// Confidence scores assigned by each heuristic rule.
const (
	ContentTypeConfidence = 0.8  // Rule 2: API content-type match.
	PathHeuristicBoost    = 0.15 // Rule 3: API path segment boost.
	HTTPMethodConfidence  = 0.7  // Rule 4: Non-GET HTTP method signal.
	JSONBodyConfidence    = 0.85 // Rule 5: JSON response structure.
	// RequestSignalConfidence is assigned by Rule 6 when a request shows explicit
	// API intent — a JSON/XML Accept or request content-type — even if no response
	// was captured, and regardless of whether the path is in apiPathSegments
	// (Phase 3 un-gated this from the path allowlist). It is deliberately set at
	// or above DefaultConfidenceThreshold so a JSON API reached by GET whose
	// response arrived too late to capture still classifies — the REST-vs-not
	// verdict then depends on the request, not on response timing (LAB-4678, B2).
	RequestSignalConfidence = 0.6
)

// RESTClassifier classifies REST API requests using ordered heuristic rules.
type RESTClassifier struct{}

// Name returns the classifier name.
func (c *RESTClassifier) Name() string {
	return "rest"
}

// Classify determines if the request is a REST API call.
func (c *RESTClassifier) Classify(req crawl.ObservedRequest) (bool, float64) {
	isAPI, confidence, _ := c.ClassifyDetail(req)
	return isAPI, confidence
}

// ClassifyDetail returns classification result with a detailed reason string.
//
// Heuristic rules applied in order:
//  1. Static asset exclusion → (false, 0, "")
//  2. Content-type filter → confidence 0.8
//  3. Path heuristics → boost +0.15 (cap 1.0)
//  4. HTTP method signal → confidence max(current, 0.7)
//  5. Response structure → confidence max(current, 0.85)
//  6. Request-side API signal (Accept / request content-type) → max(current, 0.6)
func (c *RESTClassifier) ClassifyDetail(req crawl.ObservedRequest) (bool, float64, string) { //nolint:gocyclo // multi-signal heuristic classifier
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return false, 0, ""
	}

	lowerPath := strings.ToLower(parsedURL.Path)

	// Rule 1: Static asset exclusion.
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return false, 0, ""
		}
	}
	for _, seg := range staticPathSegments {
		if strings.Contains(lowerPath, seg) {
			return false, 0, ""
		}
	}

	var confidence float64
	var reason string

	// Rule 2: Content-type filter. rule2CT records the API media type matched
	// on the response so Rule 6 can avoid re-reporting the same content type as
	// a request-side signal (QUAL-005).
	respCT := req.Response.ContentType
	if respCT == "" {
		respCT = mediatype.Header(req.Response.Headers, "content-type")
	}
	rule2CT := matchAPIContentType(respCT)
	if rule2CT != "" {
		confidence = ContentTypeConfidence
		reason = appendReason(reason, "content-type:"+rule2CT)
	}

	// pathIsAPI drives Rule 3's confidence boost. It is computed once here rather
	// than inline so the API-path scan runs once per call (QUAL-003). Rule 6 no
	// longer consults it: Phase 3 deliberately un-gated the request-side signal
	// from the path allowlist (see Rule 6).
	pathIsAPI := false
	for _, seg := range apiPathSegments {
		if strings.Contains(lowerPath, seg) {
			pathIsAPI = true
			break
		}
	}

	// Rule 3: Path heuristics.
	if pathIsAPI {
		confidence += PathHeuristicBoost
		if confidence > 1.0 {
			confidence = 1.0
		}
		reason = appendReason(reason, "path-heuristic")
	}

	// Rule 4: HTTP method signal.
	// Every rule that detects its signal appends to the reason (not only when
	// the reason is still empty) so the reason lists ALL contributing signals
	// and matches the final confidence. Otherwise a POST on an /api/ path would
	// report reason=path-heuristic (0.15) while confidence is 0.70 from this
	// rule — attributing the score to the wrong signal.
	upper := strings.ToUpper(req.Method)
	if upper == "POST" || upper == "PUT" || upper == "PATCH" || upper == "DELETE" {
		if confidence < HTTPMethodConfidence {
			confidence = HTTPMethodConfidence
		}
		reason = appendReason(reason, "method:"+upper)
	}

	// Rule 5: Response structure (JSON body).
	// Forward-only scan: find first non-whitespace byte without scanning
	// the entire body from both ends (avoids O(n) scan on large bodies).
	if len(req.Response.Body) > 0 {
		if b, ok := firstNonSpace(req.Response.Body); ok && (b == '{' || b == '[') {
			if confidence < JSONBodyConfidence {
				confidence = JSONBodyConfidence
			}
			reason = appendReason(reason, "response-structure:json")
		}
	}

	// Rule 6: Request-side API signal (LAB-4678, B2 + Phase 3 "beyond allowlists").
	// Rules 2 and 5 need a fully-arrived response, so a JSON API reached by GET
	// whose response was captured half-finished (empty content-type and body)
	// falls to the path boost alone (0.15) and is dropped — making the
	// REST-vs-not verdict a function of response timing rather than a property
	// of the app.
	//
	// An EXPLICIT API media type in the request itself — a JSON/XML Accept the
	// client asked for, or a JSON/XML request Content-Type it sent — is API
	// intent on ANY path, not only allowlisted ones (Phase 3). The hardcoded
	// apiPathSegments are not exhaustive, so gating this signal on them was
	// blind by construction to APIs on non-standard paths. Dropping the path
	// gate is guarded against over-classification: acceptSignalsAPI treats
	// text/html and application/xhtml+xml as navigation and never matches the
	// */* wildcard, so plain page loads and non-committal fetches contribute
	// nothing here. Non-GET methods are already covered by Rule 4 (0.7); this
	// closes the GET-with-explicit-JSON-intent gap regardless of path.
	signal := ""
	if apiCT := acceptSignalsAPI(mediatype.Header(req.Headers, "accept")); apiCT != "" {
		signal = "accept:" + apiCT
	}
	if signal == "" {
		// Only surface a request content-type signal that Rule 2 did not
		// already record for the same media type; otherwise the -v reason
		// would carry both "content-type:X" and "request-signal:content-type:X",
		// which convey the same fact (QUAL-005).
		if apiCT := matchAPIContentType(mediatype.Header(req.Headers, "content-type")); apiCT != "" && apiCT != rule2CT {
			signal = "content-type:" + apiCT
		}
	}
	if signal != "" {
		if confidence < RequestSignalConfidence {
			confidence = RequestSignalConfidence
		}
		reason = appendReason(reason, "request-signal:"+signal)
	}

	// There is deliberately no rule keyed on a Next.js route-handler Source.
	// An App Router route-handler chunk URL proves the PATH is served but says
	// nothing about which verbs the module exports. Classifying it as an API on
	// provenance alone made the generator emit a `get` operation for a route that
	// may export only POST, and nothing downstream corrects that: the OPTIONS
	// probe records ClassifiedRequest.AllowedMethods, but pkg/generate/rest does
	// not read it, so the invented verb survives into the spec (Codex review, PR
	// #189). A recovered route is therefore surfaced as a sub-threshold near-miss
	// under -v rather than documented as an operation that may not exist.
	// Restoring it correctly means teaching the generator to emit operations from
	// AllowedMethods, which is a separate change.

	return confidence > 0, confidence, reason
}

// appendReason joins classification signal tags with "+" so the reason string
// records every signal that contributed, in rule order. An empty existing
// reason yields the tag alone.
func appendReason(existing, sig string) string {
	if existing == "" {
		return sig
	}
	return existing + "+" + sig
}

// Structured-syntax-suffix families (RFC 6839). Returned as the match token for
// any application/<vendor>+json or +xml media type so the -v reason string stays
// a fixed vocabulary instead of echoing an unbounded vendor type.
const (
	SuffixFamilyJSON = "application/*+json"
	SuffixFamilyXML  = "application/*+xml"
)

// navigationContentTypes are document media types that must never count as an
// API signal even though one of them carries a +xml structured suffix.
// application/xhtml+xml is a page, not an API, and browsers send it on every
// navigation; without this exclusion the suffix rule below would classify every
// HTML page load as REST.
var navigationContentTypes = []string{
	"text/html", "application/xhtml+xml",
}

// soapContentTypes are SOAP media types that carry a +xml structured suffix but
// belong to WSDLClassifier, not this one. Without this exclusion the suffix tier
// would make every SOAP response count as REST as well as WSDL, inflating the
// REST tally that DetectAPIType weighs against the WSDL tally and making a
// genuinely SOAP-dominant capture unable to win its own type.
//
// text/xml is deliberately NOT here: it is a generic XML type shared by REST and
// SOAP, it predates this rule as an exact apiContentTypes entry, and removing it
// would change long-standing REST classification behavior.
var soapContentTypes = []string{
	"application/soap+xml",
}

// feedContentTypes are syndication formats. They carry a +json/+xml structured
// suffix but are content documents for feed readers, not API endpoints, so the
// suffix tier must not classify them. Vespasian maps APIs; an RSS or Atom feed
// in an OpenAPI spec is noise, and the classifier-edge live test asserts a feed
// stays out. Without this exclusion the suffix rule pulls in every blog feed on
// the target.
var feedContentTypes = []string{
	"application/rss+xml", "application/atom+xml", "application/feed+json",
}

// matchAPIContentType canonicalizes ct (lowercase + charset/parameter strip via
// mediatype.Base) and returns a stable token identifying the API media type, or
// "" if it is not an API type. Shared by Rule 2 (response content-type) and
// Rule 6 (request content-type) so both apply one matching rule (QUAL-004).
//
// Two tiers, in order:
//  1. Exact match against apiContentTypes, returning the entry itself.
//  2. RFC 6839 structured syntax suffix: any application/<vendor>+json or
//     application/<vendor>+xml, returning the suffix family token.
//
// Tier 2 exists because apiContentTypes is a closed hand-maintained list and was
// therefore blind by construction to the large open set of real API media types
// built on the +json/+xml suffixes — application/ld+json, application/geo+json,
// application/vnd.github+json, application/atom+xml and so on (LAB-4678: the
// Success criterion is that classification is not limited to hardcoded
// content-type allowlists). Matching the suffix rather than enumerating vendors
// is what removes the hardcoding.
//
// The suffix tier is narrow on purpose: it requires the application/ top-level
// type, so text/* and image/* cannot match, and three exclusion sets run first —
// navigationContentTypes (application/xhtml+xml is a page), soapContentTypes
// (owned by WSDLClassifier), and feedContentTypes (syndication documents, not
// endpoints).
func matchAPIContentType(ct string) string {
	base := mediatype.Base(ct)
	if base == "" {
		return ""
	}
	for _, nav := range navigationContentTypes {
		if base == nav {
			return ""
		}
	}
	for _, apiCT := range apiContentTypes {
		if base == apiCT {
			return apiCT
		}
	}
	if !strings.HasPrefix(base, "application/") {
		return ""
	}
	if slices.Contains(soapContentTypes, base) || slices.Contains(feedContentTypes, base) {
		return ""
	}
	switch {
	case strings.HasSuffix(base, "+json"):
		return SuffixFamilyJSON
	case strings.HasSuffix(base, "+xml"):
		return SuffixFamilyXML
	}
	return ""
}

// acceptSignalsAPI parses an Accept header and returns the API media type the
// client is explicitly asking for, or "" if none. It splits into media ranges,
// ignores q-parameters and the "*/*" wildcard, and exact-matches against
// apiContentTypes. Crucially, a header that accepts text/html or
// application/xhtml+xml is treated as a document navigation, NOT API intent —
// browsers always send those on page loads, and the standard navigation Accept
// header also contains application/xml (which would otherwise substring-match).
// This keeps Rule 6 from classifying plain HTML pages under api-like paths
// (e.g. a Swagger UI at /api/docs or a /graphql playground) as REST APIs.
func acceptSignalsAPI(accept string) string {
	if accept == "" {
		return ""
	}
	match := ""
	for _, part := range strings.Split(accept, ",") {
		mt := part
		if i := strings.Index(mt, ";"); i != -1 {
			mt = mt[:i]
		}
		mt = strings.ToLower(strings.TrimSpace(mt))
		if slices.Contains(navigationContentTypes, mt) {
			// A document-navigation marker anywhere in the header disqualifies
			// the whole request as API intent. This is stronger than
			// matchAPIContentType's own exclusion, which only rejects the single
			// type it is handed: here one navigation marker poisons the entire
			// Accept header, so "text/html, application/json" is a page load
			// rather than API intent. Both read the same list.
			return ""
		}
		if match == "" {
			// mt is already lowercased and stripped of parameters above, so
			// matchAPIContentType's mediatype.Base is a no-op on it; sharing the
			// helper keeps Rule 2, Rule 6, and this Accept branch on one matching
			// rule (QUAL-003).
			match = matchAPIContentType(mt)
		}
	}
	return match
}

// firstNonSpace returns the first non-ASCII-whitespace byte in b.
// It scans forward only, making it O(1) for typical HTTP bodies that
// start with a non-whitespace character.
func firstNonSpace(b []byte) (byte, bool) {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return c, true
		}
	}
	return 0, false
}
