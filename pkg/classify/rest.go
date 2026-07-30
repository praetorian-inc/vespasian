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

// staticExtensions lists file extensions that indicate static assets. Rule 1 of
// every classifier rejects on these, so an entry here excludes by URL regardless
// of what content-type the server sent. .webmanifest is the belt to
// documentContentTypes' braces: a manifest served with a wrong or missing
// content-type is still not an endpoint.
var staticExtensions = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".svg", ".map", ".webmanifest",
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
	// NextRouteProvenanceConfidence is assigned by Rule 7 to a route recovered from a
	// Next.js App Router chunk URL. It is a REPORTING level, not an API signal: it
	// sits at NearMissFloor so the route is listed among the -v near-misses, and far
	// below DefaultConfidenceThreshold so it can never become a spec operation with a
	// guessed verb. TestNextRouteProvenanceConfidence_IsReportingOnly pins both
	// bounds, so neither constant can drift into swallowing the other.
	NextRouteProvenanceConfidence = NearMissFloor
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
// Heuristic rules applied in order. Rules 1, 1a and 1b are DISQUALIFIERS: they
// return outright, so no later rule can promote an identified non-endpoint.
//
//	Rule 1  static asset (extension, path segment)   -> (false, 0, "")
//	Rule 1a well-known document path (documentPaths) -> (false, 0, "")
//	Rule 1b document media type                     -> (false, 0, "")
//	Rule 2  response content-type       -> confidence 0.8
//	Rule 3  path heuristics             -> boost +0.15 (cap 1.0)
//	Rule 4  non-GET method              -> max(current, 0.7)
//	Rule 5  JSON response structure     -> max(current, 0.85)
//	Rule 6  request-side API signal     -> max(current, 0.6)
//	Rule 7  Next.js chunk provenance    -> max(current, NextRouteProvenanceConfidence),
//	        a reporting-only floor, deliberately far below the API threshold
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
	// Rule 1a: Well-known document PATHS, for documents whose served content-type
	// cannot be relied on. See documentPaths for why the extension rule and the
	// content-type rule both miss the common case.
	if isDocumentPath(lowerPath) {
		return false, 0, ""
	}

	respCT := req.Response.ContentType
	if respCT == "" {
		respCT = mediatype.Header(req.Response.Headers, "content-type")
	}

	// Rule 1b: Document media types DISQUALIFY, they are not merely a missing
	// signal. Keeping them out of matchAPIContentType only silences Rule 2; Rule 5
	// still scores any JSON-object body at JSONBodyConfidence (0.85), which clears
	// the threshold on its own. A web app manifest and a JSON Feed both have JSON
	// object bodies, so without this early return /manifest.json still landed in
	// the spec after being excluded from the content-type tier — the exclusion set
	// alone was not the fix (LAB-4678 review, QUAL-003).
	//
	// This mirrors Rule 1: an identified non-endpoint is rejected outright rather
	// than left for a later rule to promote.
	if isDocumentContentType(respCT) {
		return false, 0, ""
	}

	var confidence float64
	var reason string

	// Rule 2: Content-type filter. rule2CT records the API media type matched
	// on the response so Rule 6 can avoid re-reporting the same content type as
	// a request-side signal (QUAL-005).
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

	// Rule 7: Next.js App Router provenance — a REPORTING signal only, deliberately
	// far below the threshold.
	//
	// An App Router chunk URL proves the PATH is served but says nothing about which
	// verbs the module exports. Classifying it as an API on provenance alone made the
	// generator emit a `get` operation for a route that may export only POST, and
	// nothing downstream corrects that: the OPTIONS probe records
	// ClassifiedRequest.AllowedMethods, but pkg/generate/rest does not read it, so the
	// invented verb survives into the spec (Codex review, PR #189). So this must not
	// reach DefaultConfidenceThreshold, and NextRouteProvenanceConfidence is asserted
	// against that bound by test.
	//
	// It cannot be ZERO either, which is where this rule's absence left it. Keeping a
	// recovered route out of the spec is correct; scoring it 0 ALSO put it below
	// classify.NearMissFloor, so NearMisses dropped it and it appeared in no output at
	// all. That hit the headline case squarely: /vaults/{vaultId} matches no
	// apiPathSegments entry, so it had no path boost to fall back on either. The only
	// recovered routes an operator could see were the ones that happened to sit under
	// /api/, visible via the path heuristic rather than via anything this feature
	// contributed. Meanwhile README.md, CLAUDE.md, pkg/analyze/jsstatic/doc.go and this
	// rule's own predecessor comment all asserted that recovered routes surface as
	// sub-threshold near-misses under -v. Pinning the score to the near-miss floor is
	// what makes those four claims true.
	//
	// Restoring them as real operations means teaching the generator to emit from
	// AllowedMethods, which is still a separate change.
	if req.Source == crawl.SourceNextRouteHandler || req.Source == crawl.SourceNextPageRoute {
		if confidence < NextRouteProvenanceConfidence {
			confidence = NextRouteProvenanceConfidence
		}
		reason = appendReason(reason, "next-route-chunk")
	}

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

// documentContentTypes are media types that carry a +json/+xml structured suffix
// but are DOCUMENTS rather than endpoint responses, so the suffix tier must not
// classify them. Vespasian maps APIs; a document in an OpenAPI spec is noise.
//
// Membership rule, so this set stops growing one incident at a time: a type
// belongs here when its payload is consumed as a standalone document by the
// browser or a reader application, and fetching it tells you nothing about an
// endpoint's request/response contract. That is the test to apply before adding
// an entry, and the reason each entry below is present.
//
// Deliberately NOT here: application/ld+json, application/geo+json, and vendor
// types like application/vnd.github+json. Those are endpoint response bodies —
// JSON-LD served as a response IS the API's data (Hydra, ActivityPub) — and
// matchAPIContentType's whole purpose is to stop hardcoding an allowlist that
// excludes them. A <script type="application/ld+json"> block never reaches here,
// because this matches response and request Content-Type headers, not markup.
var documentContentTypes = []string{
	// Syndication feeds: a feed is a document for feed readers. Without this the
	// suffix rule pulls in every blog feed on the target. The classifier-edge
	// live test asserts a feed stays out.
	"application/rss+xml", "application/atom+xml", "application/feed+json",
	// Web app manifest: browser install metadata, served at /manifest.json or
	// /site.webmanifest by essentially every modern SPA, which is this tool's
	// target class. Omitting it added a false operation to most REST specs and
	// inflated the restCount DetectAPIType weighs (LAB-4678 review, QUAL-003).
	"application/manifest+json",
}

// documentPaths are exact request paths that are always a standalone document
// rather than an endpoint, matched at the END of the path so a subdirectory
// deployment still hits.
//
// This exists because the other two manifest defenses BOTH miss the common case.
// documentContentTypes rejects application/manifest+json, and staticExtensions
// rejects .webmanifest — so /site.webmanifest is covered either way. But the web
// app manifest is conventionally named /manifest.json, and a .json file is very
// commonly served as plain application/json (that is the default mapping in most
// servers and CDNs; only some frameworks set application/manifest+json). In that
// combination nothing fired: .json is not a static extension, application/json is
// obviously not a document type, and Rule 2 scored it 0.8 while Rule 5's JSON
// object body took it to 0.85. Measured before this rule: /manifest.json served as
// application/json classified at 0.85 and became an operation in the spec.
//
// The rest.go comment on staticExtensions called .webmanifest "the belt to
// documentContentTypes' braces: a manifest served with a wrong or missing
// content-type is still not an endpoint" — true only for the filename almost
// nobody uses. This is the belt for the one they do.
//
// Membership rule, same as documentContentTypes: the payload is consumed as a
// standalone document, and fetching it says nothing about an endpoint's contract.
// Add a path here only when the content-type cannot be trusted to identify it,
// otherwise documentContentTypes is the right place. An app with a real API at
// /manifest.json would be misclassified; that is the same accepted asymmetry as
// skipping a read-only "Payment history" control in the --interact list.
var documentPaths = []string{
	"/manifest.json",
}

// isDocumentPath reports whether lowerPath ends in one of documentPaths. Every
// entry begins with "/", so the suffix test also covers an exact match and matches
// only on a whole final segment — "/app-manifest.json" does not hit "/manifest.json".
func isDocumentPath(lowerPath string) bool {
	for _, p := range documentPaths {
		if strings.HasSuffix(lowerPath, p) {
			return true
		}
	}
	return false
}

// isDocumentContentType reports whether ct is one of the documentContentTypes,
// canonicalized the same way matchAPIContentType canonicalizes. Callers treat a
// true result as a disqualifier for the whole request, not just as the absence of
// a content-type signal — see Rule 1b in ClassifyDetail for why the distinction
// matters.
func isDocumentContentType(ct string) bool {
	base := mediatype.Base(ct)
	return base != "" && slices.Contains(documentContentTypes, base)
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
// (owned by WSDLClassifier), and documentContentTypes (feeds and web app
// manifests, which are documents rather than endpoint responses; see that set's
// membership rule before adding to it).
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
	if slices.Contains(soapContentTypes, base) || slices.Contains(documentContentTypes, base) {
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
// ignores q-parameters, and matches each range with [matchAPIContentType] — so it
// accepts the exact apiContentTypes entries AND the RFC 6839 structured-suffix
// tier, and inherits that function's navigation/SOAP/document exclusions. "*/*"
// matches nothing there, so a non-committal fetch contributes no signal.
// Crucially, a header that accepts text/html or
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
