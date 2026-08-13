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

package rest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/mediatype"
)

// capitalizeFirst capitalizes the first letter of a string (UTF-8 safe).
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[size:]
}

// inferQueryParamItemsType infers the OpenAPI items type from a slice of
// observed query-parameter values. Returns:
//   - "integer" if every value parses as int
//   - "number"  if every value parses as float (and at least one is non-int)
//   - "boolean" if every value is "true" or "false"
//   - "string"  otherwise (mixed or string)
func inferQueryParamItemsType(values []string) string {
	if len(values) == 0 {
		return "string"
	}
	allInt, allFloat, allBool := true, true, true
	for _, v := range values {
		if _, err := strconv.Atoi(v); err != nil {
			allInt = false
		}
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			allFloat = false
		}
		if v != "true" && v != "false" {
			allBool = false
		}
	}
	switch {
	case allInt:
		return "integer"
	case allFloat:
		return "number"
	case allBool:
		return "boolean"
	default:
		return "string"
	}
}

// inferQueryParamType infers the OpenAPI type from a single query parameter
// value. Used by pkg/generate/rest/form.go for form-field type inference where
// only one value per field is observed at a time. The OpenAPI generation path
// for multi-value/scalar query parameters uses inferQueryParamItemsType so the
// scalar branch of buildOperation classifies a slice of observed values
// consistently with the array branch.
//
// Implemented as a thin wrapper around inferQueryParamItemsType so the
// integer/number/boolean/string precedence stays in one place.
func inferQueryParamType(value string) string {
	return inferQueryParamItemsType([]string{value})
}

// OpenAPIGenerator generates OpenAPI 3.0 specifications.
type OpenAPIGenerator struct {
	// Format specifies the output format: "json" or "yaml" (default: "yaml")
	Format string
	// MergeSlugs enables observation-based slug promotion during path
	// normalization (see NormalizeOptions). Off by default.
	MergeSlugs bool
	// SlugThreshold is the minimum distinct values at a path position before
	// promotion. The zero value (0) is treated as 2: NormalizePathsWithNames
	// clamps any value < 2 up to 2. Ignored unless MergeSlugs is set.
	SlugThreshold int
	// TargetOrigin is the origin the run can actually vouch for — the
	// resolved target origin (crawl.ResolveTargetOrigin), derived from
	// --target-url or the capture's own HTML page, never from bundle content.
	// extractServers uses it as the primary origin for the OpenAPI servers
	// list and info.title (SEC-BE-001/SEC-BE-002) instead of trusting
	// whatever hosts happen to appear in endpoints. Empty is valid (no
	// vouched origin available); extractServers falls back to the
	// lowest-sorted dynamically observed origin in that case.
	TargetOrigin string
}

// explodeTrue is a singleton pointer target for setting the Explode field on
// OpenAPI Parameter objects. Hoisted to package level because the OpenAPI
// schema model uses `*bool` for tri-state, requiring an addressable value.
var explodeTrue = true

// endpointKey groups endpoints by normalized path, HTTP method, AND origin
// (scheme://host, via crawl.CanonicalOrigin).
//
// SEC-BE-001 (LAB-4992 review): classify.Deduplicate keys on method+path
// (host-agnostic), NormalizePathsWithNames' numeric-ID detection runs
// unconditionally, and (pre-fix) groupEndpoints itself keyed only on
// {path, method} — so a group could silently mix endpoints observed on
// different origins. buildOperation's per-operation servers override then
// derived its answer from group[0].URL alone, which is attacker-steerable:
// depending on which hostname happened to sort first, either an attacker
// origin overrode a real endpoint's origin, or an attacker-planted path was
// silently attributed to the trusted host. Folding origin into the key makes
// a mixed-origin group impossible — every group now shares exactly one
// origin, so the override (or lack of one) is always correct for its group.
// Generate resolves the resulting (path, method) slot collisions
// deterministically (see the keys sort in Generate).
type endpointKey struct {
	path   string
	method string
	origin string
}

// APIType returns the API type.
func (g *OpenAPIGenerator) APIType() string {
	return "rest"
}

// extractServers derives the OpenAPI servers list, the info.title host, and
// the set of origins deliberately EXCLUDED from the global servers list, from
// endpoints and the run's trusted targetOrigin (crawl.ResolveTargetOrigin —
// derived from --target-url or the capture's own HTML page, never from
// bundle content).
//
// SEC-BE-001/SEC-BE-002 (LAB-4992 review): the previous version derived
// servers/title from "whatever hosts appear in endpoints", filtering out
// JS-static (crawl.IsJSStaticSource) candidates UNLESS zero dynamically
// observed endpoints existed — in which case it fell back to the full,
// unfiltered set. That fallback is the DEFAULT state for a fully-offline
// capture, so a hostile bundle literal (e.g.
// fetch("https://attacker.example/collect")) that was never seen on the wire
// could become servers[0] and capture info.title outright by sorting first
// alphabetically (SEC-BE-002). Separately, in a MIXED capture (>=1 observed
// endpoint plus a JS-static endpoint on a different host), the old filter
// correctly kept the JS-static host out of the global list, but
// groupEndpoints still emitted that endpoint's path under the single global
// server — silently attributing a recovered path to a host that does not
// serve it (SEC-BE-001). buildOperation now closes that gap with a
// per-operation servers override for any endpoint whose origin is in the
// excluded set this function returns.
//
// SEC-BE-001 follow-up (LAB-4992 review): the override above was itself
// exploitable, because classify.Deduplicate, NormalizePathsWithNames, and
// (formerly) groupEndpoints all group host-agnostically — a single group
// could silently mix endpoints from different origins, and the override
// derived its answer from an arbitrary member of that mixed group. origin is
// now part of endpointKey (see its doc comment) so a group can never mix
// origins — TestGenerate_ThreeOriginCollision_RecordsAllSuppressedOrigins keeps
// three origins on one path+method in three separate groups, which a mixed group
// would collapse. Generate resolves the resulting (path, method) slot collisions
// by trust rank (see trustRank), so the most-trusted colliding group always
// wins deterministically — an excluded origin can never win over a
// non-excluded one (SEC-BE-002), regardless of which hostname sorts first.
//
// Derivation:
//  1. primary origin = targetOrigin if it parses to a usable http(s) origin;
//     else the lowest-sorted origin among DYNAMICALLY OBSERVED (non-
//     crawl.IsJSStaticSource) endpoints; else "" (no vouched origin at all).
//  2. global servers = primary (first, unsorted) + every dynamically
//     observed origin + any JS-static origin that is SAME-ORIGIN with
//     primary (crawl.SameOrigin) — sorted (LAB-4678) after the primary. A
//     cross-origin JS-static origin never enters the global list; it is
//     reported in the returned excluded set instead.
//  3. info.title derives from the primary origin only, never from a
//     cross-origin JS-static host.
//
// static:html (form-derived candidates, analyze.ExtractForms) is deliberately
// NOT treated as JS-static here: the page carrying the form was itself
// fetched over the wire during the crawl, unlike a JS-static candidate whose
// entire existence is reconstructed offline from bundle text that was never
// executed or requested. This mirrors the codebase's own established
// distinction — computeSourceTag already treats static:html the same as a
// real dynamic observation (see its doc comment) rather than as
// offline-derived — so this function reuses crawl.IsJSStaticSource, the
// single canonical definition of "unprobed JS-static", instead of inventing a
// new predicate.
func extractServers(endpoints []classify.ClassifiedRequest, targetOrigin string) (openapi3.Servers, string, map[string]bool) {
	observedOrigins, jsStaticOrigins := collectEndpointOrigins(endpoints)
	primary := choosePrimaryOrigin(targetOrigin, observedOrigins)

	serverSet := make(map[string]bool)
	var servers openapi3.Servers
	addServer := func(origin string) {
		if origin == "" || serverSet[origin] {
			return
		}
		serverSet[origin] = true
		servers = append(servers, &openapi3.Server{URL: origin})
	}

	// Primary goes first and is NOT subject to the sort below (LAB-4678's
	// determinism guarantee only needs to hold for the remainder of the
	// list; the primary's position is already deterministic by definition).
	addServer(primary)
	for _, origin := range sortedCopy(observedOrigins) {
		addServer(origin)
	}

	// "excluded" means unvouched, not merely bundle-mentioned — see the
	// package doc comment for the full semantic contract (SEC-BE-002). The
	// mechanism: serverSet already holds every origin vouched for above (the
	// primary plus each observed origin), so an origin collectEndpointOrigins
	// also placed in jsStaticOrigins (i.e. named by a bundle literal) is only
	// excluded when it is NOT already in serverSet.
	//
	// This is a single if-check inside the loop below, not a three-arm
	// switch: a prior version had a third arm admitting a jsStaticOrigin that
	// was merely crawl.SameOrigin with primary, even when not in serverSet.
	// That arm was unreachable dead code — primary and every jsStaticOrigin are
	// both crawl.CanonicalOrigin outputs (collectEndpointOrigins,
	// choosePrimaryOrigin), CanonicalOrigin is idempotent, and
	// crawl.SameOrigin over two CanonicalOrigin outputs can only agree with
	// plain string equality (TestCanonicalOrigin_SameOriginImpliesEquality,
	// pkg/crawl) — so `SameOrigin(origin, primary)` true implies
	// `origin == primary`, and primary is unconditionally added to serverSet
	// before this loop runs (addServer(primary) above), meaning the
	// `serverSet[origin]` arm above always matches first. Do not restore a
	// same-origin admission arm here without first breaking that invariant.
	excluded := make(map[string]bool)
	for _, origin := range sortedCopy(jsStaticOrigins) {
		// serverSet already holds every vouched origin (primary plus each
		// dynamically observed one), so a bundle merely naming one of them
		// cannot demote it.
		if !serverSet[origin] {
			excluded[origin] = true
		}
	}

	titleHost := "API"
	if primary != "" {
		if u, err := url.Parse(primary); err == nil && u.Host != "" {
			titleHost = u.Host + " API"
		}
	}

	return servers, titleHost, excluded
}

// collectEndpointOrigins partitions endpoints' origins (scheme://host, via
// crawl.CanonicalOrigin) into dynamically observed and JS-static buckets,
// each deduped and in first-seen order. Endpoints with an unparseable or
// non-http(s)-with-host URL are silently skipped.
func collectEndpointOrigins(endpoints []classify.ClassifiedRequest) (observed, jsStatic []string) {
	seenObserved := make(map[string]bool)
	seenJSStatic := make(map[string]bool)
	for _, ep := range endpoints {
		origin := crawl.CanonicalOrigin(ep.URL)
		if origin == "" {
			continue
		}
		if crawl.IsJSStaticSource(ep.Source) {
			if !seenJSStatic[origin] {
				seenJSStatic[origin] = true
				jsStatic = append(jsStatic, origin)
			}
			continue
		}
		if !seenObserved[origin] {
			seenObserved[origin] = true
			observed = append(observed, origin)
		}
	}
	return observed, jsStatic
}

// choosePrimaryOrigin picks the primary origin: targetOrigin if it
// canonicalizes (crawl.CanonicalOrigin) to a usable http(s) origin, else the
// lowest-sorted dynamically observed origin, else "" (no vouched origin).
func choosePrimaryOrigin(targetOrigin string, observedOrigins []string) string {
	if primary := crawl.CanonicalOrigin(targetOrigin); primary != "" {
		return primary
	}
	if len(observedOrigins) == 0 {
		return ""
	}
	sorted := sortedCopy(observedOrigins)
	return sorted[0]
}

// sortedCopy returns a sorted copy of ss, leaving the input untouched.
func sortedCopy(ss []string) []string {
	sorted := append([]string(nil), ss...)
	sort.Strings(sorted)
	return sorted
}

// groupEndpoints groups and sorts endpoints by normalized path and HTTP method.
//
// Path normalization runs in two passes so that slug-style identifiers can be
// detected from the population of observed paths. The first pass parses URLs
// and collects their paths; the second pass calls NormalizePathsWithNames
// once, which performs both regex-based and observation-based detection.
func groupEndpoints(endpoints []classify.ClassifiedRequest, opts NormalizeOptions) map[endpointKey][]classify.ClassifiedRequest {
	type parsedEndpoint struct {
		path     string
		endpoint classify.ClassifiedRequest
	}
	parsed := make([]parsedEndpoint, 0, len(endpoints))
	rawPaths := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		parsedURL, err := url.Parse(endpoint.URL)
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
			// Skip malformed URLs or non-HTTP/HTTPS schemes
			continue
		}
		parsed = append(parsed, parsedEndpoint{path: parsedURL.Path, endpoint: endpoint})
		rawPaths = append(rawPaths, parsedURL.Path)
	}

	normalized := NormalizePathsWithNames(rawPaths, opts)

	endpointGroups := make(map[endpointKey][]classify.ClassifiedRequest)
	for _, p := range parsed {
		// origin ("" if unparseable/host-less) is part of the key (SEC-BE-001)
		// so a group can never mix endpoints from different origins
		// (TestGenerate_ThreeOriginCollision_RecordsAllSuppressedOrigins).
		origin := crawl.CanonicalOrigin(p.endpoint.URL)
		key := endpointKey{path: normalized[p.path], method: strings.ToLower(p.endpoint.Method), origin: origin}
		endpointGroups[key] = append(endpointGroups[key], p.endpoint)
	}
	return endpointGroups
}

// anyStaticSource returns true if any request in endpoints carries a JS-bundle
// static-analysis source. The x-vespasian-source extension is gated on this so
// that flag-off output (and inputs from sources outside LAB-2108) stay
// byte-identical to pre-LAB-2108 behavior. Non-JS static sources do not gate.
//
// The per-element check is delegated to crawl.IsJSStaticSource, which owns the
// canonical definition of the JS-static Source vocabulary. The local wrapper
// exists only to accept []classify.ClassifiedRequest (which embeds
// crawl.ObservedRequest) rather than []crawl.ObservedRequest.
func anyStaticSource(endpoints []classify.ClassifiedRequest) bool {
	for _, ep := range endpoints {
		if crawl.IsJSStaticSource(ep.Source) {
			return true
		}
	}
	return false
}

// jsStaticSourceRank orders the JS-static friendly tags from most to least
// confident: a directly AST-recovered literal is most confident, a sourcemap
// recovery is next (recovered from original source, not the served bundle),
// then a concat/service-prefix reconstruction (never probed, speculative), and
// last the two Next.js chunk-URL recoveries, which have no body evidence at all
// — the chunk path proves only that the framework serves the route, and a page
// route is navigational rather than an endpoint. computeSourceTag uses this so a
// group mixing distinct JS-static tags resolves to the LEAST-CONFIDENT member,
// not "dynamic".
//
// Every tag friendlySourceTag can return needs an entry. A missing one reads as
// rank 0 from this map, which collides with js-bundle — the MOST-confident label
// — and TestJSStaticSourceRank_CoversEveryFriendlyTag fails on the gap.
var jsStaticSourceRank = map[string]int{
	"js-bundle":        0,
	"js-sourcemap":     1,
	"js-bundle-concat": 2,
	"js-nextroute":     3,
	"js-nextpage":      4,
}

// leastConfidentJSStaticTag is the highest-ranked entry in jsStaticSourceRank.
// Derived rather than written out because computeSourceTag falls back to it for a
// JS-static source that friendlySourceTag does not name, and a literal here would
// silently stop being the last tag the next time a rank is added.
var leastConfidentJSStaticTag = func() string {
	tag, rank := "", -1
	for t, r := range jsStaticSourceRank {
		if r > rank {
			tag, rank = t, r
		}
	}
	return tag
}()

// computeSourceTag derives the x-vespasian-source value for an operation group.
// Mapping (architecture.md §7):
//   - any request whose Source is not JS-static (including empty Source from
//     pre-LAB-2108 captures, untagged dynamic entries, AND non-JS static
//     sources like "static:html")                    → "dynamic"
//   - all requests Source == "static:js"             → "js-bundle"
//   - all requests Source == "static:js-sourcemap"   → "js-sourcemap"
//   - all requests Source == "static:js-concat"      → "js-bundle-concat"
//   - all requests Source == "static:js-nextroute"   → "js-nextroute"
//   - all requests Source == "static:js-nextpage"    → "js-nextpage"
//   - mixed JS-static tags within a group (all requests JS-static, but not all
//     the SAME friendly tag) → the LEAST-CONFIDENT member present, per
//     jsStaticSourceRank, e.g. js-bundle + js-bundle-concat → "js-bundle-concat"
//   - empty group (len(group) == 0)                  → "" (no extension emitted)
//
// For non-empty input the function always returns "dynamic" or one of the five
// named values. TestFriendlySourceTag_TotalOverJSStaticSources asserts that every
// source crawl.IsJSStaticSource accepts has a name here, so the two cannot drift.
//
// "dynamic" is reserved strictly for a group containing a real non-JS-static
// source (dynamic / static:html / empty). An all-JS-static group, even when it
// mixes distinct JS-static tags, must never resolve to "dynamic", since that is
// the HIGHEST-confidence label and would make a group recovered entirely from
// offline JS analysis look directly observed (QUAL-003). The "js-bundle-concat"
// value (LAB-4992 / SEC-BE-001) flags never-probed concat/service-prefix
// reconstructions, and the two Next.js values flag routes recovered from a chunk
// URL alone, so consumers can weight both below AST-recovered literals.
//
// The empty-group case is unreachable in current usage because groupEndpoints
// only creates a key when at least one ClassifiedRequest matches; this contract
// is documented for defense-in-depth so future callers can rely on it.
//
// This is intentionally a closed allow-list rather than a strings.TrimPrefix
// open list — a new "static:foo" source must NOT silently surface as
// x-vespasian-source: foo, because the extension is a consumer contract.
//
// Naming is LOCAL to friendlySourceTag rather than delegated to
// crawl.IsJSStaticSource. IsJSStaticSource owns "is this a JS-bundle static
// source" for the extension-emission gate (anyStaticSource); friendlySourceTag
// owns "what does the consumer contract call it". Keeping the two in sync is the
// test's job, not an assumption: when the Next.js tags were added to
// IsJSStaticSource and not here, an all-nextroute group returned "" (no extension
// at all) and a mixed group returned "dynamic", falsely claiming the endpoint had
// been dynamically observed when it was recovered from a chunk URL and never
// requested. That was reachable at --confidence 0.1 before RESTClassifier started
// returning isAPI=false for these sources. The two are consulted separately here
// so an out-of-sync JS-static source degrades to the least-confident tag instead
// of borrowing "dynamic", which is the highest-confidence label.
func computeSourceTag(group []classify.ClassifiedRequest) string {
	if len(group) == 0 {
		return ""
	}
	leastConfident := ""
	leastConfidentRank := -1
	for _, ep := range group {
		friendly, ok := friendlySourceTag(ep.Source)
		switch {
		case ok:
		case !crawl.IsJSStaticSource(ep.Source):
			// A real non-JS-static source — dynamic, empty, or static:html — is
			// "dynamic", matching the documented catch-all above.
			return "dynamic"
		default:
			// QUAL-005: a JS-static source friendlySourceTag does not name must
			// still map to a real tag. Leaving friendly == "" made
			// jsStaticSourceRank[""] return the zero value — which COLLIDES with
			// js-bundle's rank 0, the most-confident label. The unknown source
			// would then win the first comparison (0 > -1), and a later genuine
			// js-bundle would fail 0 > 0, so the function returned "" and
			// suppressed the x-vespasian-source extension for the whole group.
			// crawl.IsJSStaticSource (pkg/crawl) and friendlySourceTag live in
			// different packages and must be edited together, so the miss is
			// reachable by a one-sided edit — this PR itself required exactly that
			// two-site change, twice.
			//
			// Resolve to the least-confident known tag: an unrecognized JS-static
			// source is still offline-derived, so understating provenance is the
			// safe direction, and it can never suppress the extension or
			// masquerade as "dynamic". TestJSStaticSourceRank_CoversEveryFriendlyTag
			// keeps that fallback pointing at a ranked tag, which is what makes the
			// claim hold — an unranked one would reintroduce the rank-0 collision.
			friendly = leastConfidentJSStaticTag
		}
		if r := jsStaticSourceRank[friendly]; r > leastConfidentRank {
			leastConfidentRank = r
			leastConfident = friendly
		}
	}
	return leastConfident
}

// friendlySourceTag maps a Source to its x-vespasian-source value, reporting false
// for any source the consumer contract does not name. Keeping this total — every
// input gets an answer — is what stops a newly added Source constant from producing
// an empty tag by falling through a switch.
func friendlySourceTag(source string) (string, bool) {
	switch source {
	case crawl.SourceStaticJS:
		return "js-bundle", true
	case crawl.SourceStaticJSSourcemap:
		return "js-sourcemap", true
	case crawl.SourceStaticJSConcat:
		return "js-bundle-concat", true
	case crawl.SourceNextRouteHandler:
		return "js-nextroute", true
	case crawl.SourceNextPageRoute:
		return "js-nextpage", true
	default:
		return "", false
	}
}

// mergeJSONBodies infers and merges JSON schemas from multiple body observations.
func mergeJSONBodies(bodies [][]byte) *openapi3.SchemaRef {
	var merged *openapi3.SchemaRef
	for _, body := range bodies {
		if len(body) == 0 {
			continue
		}
		schema := InferSchema(body)
		if schema == nil {
			continue
		}
		// Delegate to mergeObjectSchemas (defined in form.go) so JSON, urlencoded,
		// and multipart all share the same conflict-resolution semantics: union
		// of properties; conflicting types promote to string.
		merged = mergeObjectSchemas(merged, schema)
	}
	return merged
}

// maxSchemaUnionDepth bounds the recursion in unionSchemaProperties against a
// pathological or deeply-nested inferred schema.
const maxSchemaUnionDepth = 12

// responseObservations flattens a group into every response the union should
// consider: each member's retained Response, followed by the responses
// classify.Deduplicate collapsed into it (ClassifiedRequest.MergedResponses).
//
// Without the merged half, the union below could only ever combine responses
// belonging to DIFFERENT group members, and Deduplicate has already collapsed
// same-endpoint observations into one member — its key hashes the request body,
// so every bodyless observation of one endpoint becomes a single entry. For a
// collection GET that left exactly one response to "union", which is why the
// array-items recursion, written for GET /users returning [{"id":1,"name":"a"}]
// then [{"id":2,"email":"b@x"}], never fired on that input.
//
// Order follows the group's existing deterministic order, and within a member
// the retained response precedes its merged ones, so the emitted schema does not
// depend on capture order.
func responseObservations(group []classify.ClassifiedRequest) []crawl.ObservedResponse {
	out := make([]crawl.ObservedResponse, 0, len(group))
	for _, ep := range group {
		out = append(out, ep.Response)
		out = append(out, ep.MergedResponses...)
	}
	return out
}

// unionSchemaProperties merges src's object properties into dst additively
// (LAB-4678 Phase 3): a property present in src but missing from dst is added,
// and a property present in both whose value is itself an object is merged
// recursively, so fields observed in only some responses of the same
// endpoint+status are preserved rather than dropped after the first observation.
// It never removes or retypes an existing property, so it cannot narrow the
// documented schema. depth bounds the recursion.
//
// Array schemas are entered through Items. A collection endpoint is the common
// case for partial observations — GET /users returning [{"id":1,"name":"a"}] and
// later [{"id":2,"email":"b@x"}] — and because an array schema has no Properties
// of its own, recursing only through Properties never reached the item schema and
// the second observation's `email` was dropped. Items consumes one depth level,
// same as a nested object, so the existing bound still holds.
func unionSchemaProperties(dst, src *openapi3.Schema, depth int) {
	if dst == nil || src == nil || depth <= 0 {
		return
	}
	if dst.Items != nil && src.Items != nil {
		unionSchemaProperties(dst.Items.Value, src.Items.Value, depth-1)
	}
	if dst.Properties == nil || src.Properties == nil {
		return
	}
	for name, srcRef := range src.Properties {
		dstRef, exists := dst.Properties[name]
		if !exists {
			dst.Properties[name] = srcRef
			continue
		}
		if dstRef != nil && dstRef.Value != nil && srcRef != nil && srcRef.Value != nil {
			unionSchemaProperties(dstRef.Value, srcRef.Value, depth-1)
		}
	}
}

// buildOperation builds a single OpenAPI operation from a group of classified requests.
// emitSource controls whether the x-vespasian-source extension is set on the operation.
// It should be true only when at least one request in the entire Generate input carries
// a "static:*" Source value (so flag-off output stays byte-identical to pre-LAB-2108).
//
// excludedOrigins is the set of origins extractServers excluded from the
// global servers list (cross-origin JS-static candidates, SEC-BE-001). When
// the group's own origin (key.origin — every entry in the group shares this
// origin since origin is now part of endpointKey) is in that set, the
// operation gets a per-operation `servers` override naming its own origin —
// otherwise groupEndpoints would still emit this path under the single
// global server, silently attributing a recovered path to a host that does
// not serve it.
func buildOperation(key endpointKey, group []classify.ClassifiedRequest, emitSource bool, excludedOrigins map[string]bool) *openapi3.Operation { //nolint:gocyclo // OpenAPI operation builder
	operation := &openapi3.Operation{
		Summary:   capitalizeFirst(key.method) + " " + key.path,
		Responses: &openapi3.Responses{},
	}

	if len(group) == 0 {
		return operation
	}

	// Order the group deterministically before any first-seen-wins logic below
	// (LAB-4678, M3). A group holds every observation that normalized to this
	// path+method, including multiple dedup entries with distinct request
	// bodies, each carrying its own response. The response merge (per status
	// code) keeps the first-seen response as the base, and the query-param and
	// body unions consume the group in order. The group arrives in the crawl's
	// capture order — nondeterministic — so without this sort the documented
	// response (and any conflict tie-break) could differ run-to-run for a fixed
	// input. Each entry's response was already selected deterministically in
	// classify.Deduplicate; ordering the entries makes their combination
	// deterministic too. Key: URL, method, request body, then response fields.
	sort.SliceStable(group, func(i, j int) bool {
		a, b := group[i], group[j]
		if a.URL != b.URL {
			return a.URL < b.URL
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		if c := bytes.Compare(a.Body, b.Body); c != 0 {
			return c < 0
		}
		return classify.CompareResponses(a.Response, b.Response) < 0
	})

	// SEC-BE-001: a cross-origin JS-static endpoint's origin was excluded from
	// the global servers list by extractServers; give the operation its own
	// `servers` override so it is never silently attributed to the primary
	// host. key.origin is authoritative for the whole group (origin is part
	// of endpointKey), so no mixed-origin group can produce a wrong answer.
	if key.origin != "" && excludedOrigins[key.origin] {
		operation.Servers = &openapi3.Servers{&openapi3.Server{URL: key.origin}}
	}

	// --- Query parameters: collect union from all endpoints, track frequency, values, and multi-value ---
	type queryParamInfo struct {
		count          int      // # of endpoints observing this param (for `required`)
		values         []string // union of ALL values seen, order-preserved (for items inference + array detection)
		multiValueSeen bool     // true iff any single observation had >1 values
	}
	queryParams := make(map[string]*queryParamInfo)
	endpointsWithParams := 0
	for _, ep := range group {
		if len(ep.QueryParams) > 0 {
			endpointsWithParams++
		}
		for name, vals := range ep.QueryParams {
			info, ok := queryParams[name]
			if !ok {
				info = &queryParamInfo{}
				queryParams[name] = info
			}
			info.count++
			// Prefer the per-observation truth recorded by RunClassifiers
			// (MultiValueQueryKeys) — that survives Deduplicate's
			// union-merge, whereas len(vals) > 1 here can falsely fire
			// when dedup merged two scalar observations of the same key
			// with different values. Fall back to len-based detection
			// only when MultiValueQueryKeys is nil (direct test
			// construction that doesn't go through RunClassifiers).
			if ep.MultiValueQueryKeys != nil {
				if ep.MultiValueQueryKeys[name] {
					info.multiValueSeen = true
				}
			} else if len(vals) > 1 {
				info.multiValueSeen = true
			}
			info.values = classify.MergeUniqueOrdered(info.values, vals)
		}
	}
	if len(queryParams) > 0 {
		// Sort parameter names for deterministic output
		paramNames := make([]string, 0, len(queryParams))
		for name := range queryParams {
			paramNames = append(paramNames, name)
		}
		sort.Strings(paramNames)

		operation.Parameters = make(openapi3.Parameters, 0, len(queryParams))
		for _, name := range paramNames {
			info := queryParams[name]
			// Required if present in all endpoints that have query params
			required := endpointsWithParams > 0 && info.count == endpointsWithParams

			if len(info.values) == 0 {
				continue // No observed values; cannot document this parameter accurately.
			}

			var param *openapi3.Parameter
			if info.multiValueSeen {
				// Emit array parameter with items type, style=form, explode=true
				itemsType := inferQueryParamItemsType(info.values)
				schema := &openapi3.Schema{
					Type: &openapi3.Types{"array"},
					Items: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type: &openapi3.Types{itemsType},
						},
					},
				}
				param = &openapi3.Parameter{
					Name:     name,
					In:       "query",
					Required: required,
					Schema:   &openapi3.SchemaRef{Value: schema},
					Style:    "form",
					Explode:  &explodeTrue,
				}
			} else {
				// Emit scalar parameter; walk all observed values so type
				// inference is order-independent (e.g., "1" then "1.5" → number).
				paramType := inferQueryParamItemsType(info.values)
				param = &openapi3.Parameter{
					Name:     name,
					In:       "query",
					Required: required,
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type: &openapi3.Types{paramType},
						},
					},
				}
			}
			operation.Parameters = append(operation.Parameters, &openapi3.ParameterRef{Value: param})
		}
	}

	// Add path parameters (extract from normalized path dynamically)
	pathParamNames := extractPathParams(key.path)
	for _, paramName := range pathParamNames {
		param := &openapi3.Parameter{
			Name:     paramName,
			In:       "path",
			Required: true,
			Schema: &openapi3.SchemaRef{
				Value: &openapi3.Schema{
					Type: &openapi3.Types{"string"},
				},
			},
		}
		operation.Parameters = append(operation.Parameters, &openapi3.ParameterRef{Value: param})
	}

	// --- Request body: partition by content type and merge ---
	if key.method == "post" || key.method == "put" || key.method == "patch" {
		type bodyObs struct {
			body        []byte
			contentType string
		}
		ctGroups := map[string][]bodyObs{}

		for _, ep := range group {
			if len(ep.Body) == 0 {
				continue
			}
			ct := mediatype.Header(ep.Headers, "content-type")
			baseType := "application/json"
			if ct != "" {
				if t := mediatype.Base(ct); t != "" {
					baseType = t
				}
			}
			ctGroups[baseType] = append(ctGroups[baseType], bodyObs{body: ep.Body, contentType: ct})
		}

		if len(ctGroups) > 0 {
			content := openapi3.Content{}
			ctKeys := make([]string, 0, len(ctGroups))
			for k := range ctGroups {
				ctKeys = append(ctKeys, k)
			}
			sort.Strings(ctKeys)
			for _, mediaType := range ctKeys {
				obs := ctGroups[mediaType]
				bodies := make([][]byte, len(obs))
				contentTypes := make([]string, len(obs))
				for i, o := range obs {
					bodies[i] = o.body
					contentTypes[i] = o.contentType
				}
				var schema *openapi3.SchemaRef
				switch mediaType {
				case "application/x-www-form-urlencoded":
					schema = mergeURLEncodedBodies(bodies)
				case "multipart/form-data":
					schema = mergeMultipartBodies(bodies, contentTypes)
				default:
					schema = mergeJSONBodies(bodies)
				}
				if schema != nil {
					content[mediaType] = &openapi3.MediaType{Schema: schema}
				}
			}
			if len(content) > 0 {
				operation.RequestBody = &openapi3.RequestBodyRef{
					Value: &openapi3.RequestBody{
						Content: content,
					},
				}
			}
		}
	}

	// --- Responses: collect all distinct status codes, merge schemas ---
	seenStatus := make(map[string]*openapi3.ResponseRef)
	for _, resp := range responseObservations(group) {
		statusCode := "200"
		statusInt := 200
		if sc := resp.StatusCode; sc > 0 {
			statusCode = strconv.Itoa(sc)
			statusInt = sc
		}

		if existing, ok := seenStatus[statusCode]; ok {
			// Merge response body schema if this observation has a JSON body.
			// The base (first observation of this status in the deterministically
			// sorted group) may itself be a half-captured empty response, so we
			// must also ADOPT a populated schema when the base has none — not
			// only union into an already-populated base. Otherwise a populated
			// observation is silently dropped whenever an empty one sorts first
			// (review finding 002).
			if len(resp.Body) > 0 && existing.Value != nil {
				// Only infer JSON schema for JSON-compatible content types
				ct := strings.ToLower(resp.ContentType)
				if ct == "" || strings.Contains(ct, "json") {
					newSchema := InferSchema(resp.Body)
					if newSchema != nil && newSchema.Value != nil {
						if existing.Value.Content == nil {
							// Base had no body; adopt this populated schema.
							// Accept ANY inferred schema, not only objects: a JSON
							// array or scalar body has nil Properties, so gating on
							// Properties!=nil here dropped populated array/scalar
							// responses whenever an empty base sorted first. This
							// mirrors the base-creation path below, which adopts any
							// non-nil schema (Codex/CodeRabbit review).
							existing.Value.Content = openapi3.Content{
								"application/json": &openapi3.MediaType{Schema: newSchema},
							}
						} else if mt := existing.Value.Content["application/json"]; mt != nil && mt.Schema != nil &&
							mt.Schema.Value != nil &&
							(mt.Schema.Value.Properties != nil || mt.Schema.Value.Items != nil) {
							// Union additively and recursively (LAB-4678 Phase 3):
							// a field seen in only some observations of this
							// endpoint+status is preserved even when nested under a
							// shared parent object, not just at the top level.
							//
							// The Items arm of this guard is load-bearing. A top-level
							// JSON array — the common collection endpoint, GET /users
							// returning [{"id":1,"name":"a"}] then [{"id":2,"email":..}]
							// — has nil Properties, since its fields live under Items.
							// Gating on Properties alone made unionSchemaProperties'
							// array recursion unreachable for exactly the case it was
							// written for, silently dropping later observations' fields.
							// Scalar schemas have neither and still skip the union.
							unionSchemaProperties(mt.Schema.Value, newSchema.Value, maxSchemaUnionDepth)
						}
					}
				}
			}
			continue
		}

		description := http.StatusText(statusInt)
		if description == "" {
			description = statusCode
		}
		response := &openapi3.Response{
			Description: &description,
		}

		if len(resp.Body) > 0 {
			// Only infer JSON schema for JSON-compatible content types
			ct := strings.ToLower(resp.ContentType)
			if ct == "" || strings.Contains(ct, "json") {
				schema := InferSchema(resp.Body)
				if schema != nil {
					response.Content = openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: schema,
						},
					}
				}
			}
		}

		ref := &openapi3.ResponseRef{Value: response}
		seenStatus[statusCode] = ref
		operation.Responses.Set(statusCode, ref)
	}

	// Remove empty default response if we have real responses
	if operation.Responses != nil && operation.Responses.Len() > 0 {
		// Check if default exists
		if defaultResp := operation.Responses.Value("default"); defaultResp != nil {
			// Only remove if it's empty (no description or empty description)
			if defaultResp.Value != nil && (defaultResp.Value.Description == nil || *defaultResp.Value.Description == "") {
				operation.Responses.Delete("default")
			}
		}
	}

	// LAB-2108: x-vespasian-source extension.
	// Only emit when the overall Generate input contained at least one static: source
	// (emitSource=true), preventing any change to output for flag-off/legacy captures.
	if emitSource {
		if src := computeSourceTag(group); src != "" {
			if operation.Extensions == nil {
				operation.Extensions = map[string]any{}
			}
			operation.Extensions["x-vespasian-source"] = src
		}
	}

	return operation
}

// recordCollisionOrigin records, on the winning operation of a (path,
// method) slot collision (SEC-BE-001), the origin of a group that lost that
// collision and so could not be emitted. There is exactly one Operation slot
// per (path, method) in doc.Paths, so the losing group's endpoint cannot be
// represented as its own operation — but its loss must never be silent.
// x-vespasian-collision-origins lists every suppressed origin, deduplicated
// and sorted for determinism, in the same extension style as
// x-vespasian-source.
//
// origin can be "" (TEST-001, LAB-4992 review): a suppressed group's
// endpointKey.origin is crawl.CanonicalOrigin's result for its member
// endpoints' URL, which is "" for a host-less literal such as
// "https:/api/x". This is deliberate, not a gap — the empty string is
// itself informative here (it names WHICH unknown-provenance candidate
// lost, consistent with trustRank ranking "" as least trusted), and every
// caller of this function already has a non-empty winner to attach it to.
func recordCollisionOrigin(winner *openapi3.Operation, origin string) {
	if winner.Extensions == nil {
		winner.Extensions = map[string]any{}
	}
	var existing []string
	if v, ok := winner.Extensions["x-vespasian-collision-origins"].([]string); ok {
		existing = v
	}
	for _, o := range existing {
		if o == origin {
			return
		}
	}
	existing = append(existing, origin)
	sort.Strings(existing)
	winner.Extensions["x-vespasian-collision-origins"] = existing
}

// trustRank orders an origin by how much this run can vouch for it, lowest
// = most trusted. Generate's keys sort (below) tie-breaks a (path, method)
// slot collision by this rank rather than by the origin string itself, so
// that a colliding slot is always won by the most trusted origin present:
//
//	0 — the primary origin (the run's vouched origin; see choosePrimaryOrigin).
//	    A JS-static origin that is same-origin with primary (crawl.SameOrigin)
//	    also lands here, NOT in rank 1 below: extractServers admits it via the
//	    same crawl.CanonicalOrigin every origin in this function is compared
//	    with, so its canonicalized string is identical to primaryOrigin's —
//	    `origin == primaryOrigin` is true for it (QUAL-001: an earlier version
//	    of this comment placed it in rank 1, which the code never does).
//	1 — any other non-excluded, non-empty origin: a dynamically observed
//	    origin distinct from primary. Already passed extractServers'
//	    admission and sits in the global servers list.
//	2 — an excluded origin (cross-origin JS-static, never probed, and named
//	    only by content the run does not control) OR an origin of unknown
//	    provenance ("" — see below)
//
// INVARIANT: an origin this run cannot vouch for — excluded OR of unknown
// provenance — must NEVER win a (path, method) slot that a vouched
// (non-excluded, non-empty) origin also claims.
//
// SEC-BE-002 (LAB-4992 review): the prior tie-break compared each colliding
// origin to primaryOrigin as a single boolean (iPrimary/jPrimary). That
// abstains whenever NEITHER colliding origin IS the primary — a real,
// dynamically-observed endpoint (e.g. captured on a different page than the
// primary) colliding with an excluded, cross-origin JS-static literal falls
// straight through to a plain byte-compare of the origin strings, so an
// attacker who controls the JS-static literal's URL can win the slot simply
// by choosing a hostname that sorts first. This 3-level rank makes that
// case explicit and impossible: rank 2 (excluded) can never beat rank 0 or
// 1 (not excluded), regardless of which hostname sorts first.
// TestGenerate_CollisionNeitherOriginPrimary_TrustRankPicksObservedOverExcluded
// runs it with the attacker hostname sorting both before and after the real one.
//
// TEST-001 (LAB-4992 review): an empty origin — crawl.CanonicalOrigin's
// result for a host-less literal such as "https:/api/x" (single slash, not
// an authority marker) — is skipped by collectEndpointOrigins, so "" never
// enters excludedOrigins; it used to fall to the default case (rank 1),
// defeating the invariant above for exactly the origin this run knows
// LEAST about. Worse, `origin == primaryOrigin` was checked FIRST, and
// primaryOrigin is itself "" whenever choosePrimaryOrigin cannot vouch for
// any origin at all (no usable TargetOrigin and no dynamically observed
// endpoint) — so an empty origin then matched THAT arm and ranked 0, the
// MOST trusted of all. The empty-origin case is now checked first and
// explicitly, so it can never be short-circuited by an empty primaryOrigin.
func trustRank(origin, primaryOrigin string, excludedOrigins map[string]bool) int {
	switch {
	case origin == "":
		return 2
	case origin == primaryOrigin:
		return 0
	case excludedOrigins[origin]:
		return 2
	default:
		return 1
	}
}

// resolveCollisions builds each key's operation and places it into
// doc.Paths, resolving (path, method) slot collisions between groups whose
// paths and methods normalize identically but whose origins differ
// (SEC-BE-001/SEC-BE-002). keys must already be sorted (see Generate) so
// that, for any set of keys colliding on the same (path, method), the
// lowest-trustRank (most trusted) key is the first one encountered for that
// slot — every later key for the same slot is a loser whose origin is
// recorded via recordCollisionOrigin instead of building a second,
// unreachable Operation.
func resolveCollisions(doc *openapi3.T, keys []endpointKey, endpointGroups map[endpointKey][]classify.ClassifiedRequest, staticPresent bool, excludedOrigins map[string]bool) {
	// occupiedSlots tracks which (path, method) slot each already-built
	// operation occupies, so a later colliding group (same path+method,
	// different origin) is detected rather than silently overwriting the
	// winner set by the caller's sort.
	type slot struct{ path, method string }
	occupiedSlots := make(map[slot]*openapi3.Operation)

	for _, key := range keys {
		group := endpointGroups[key]

		// Build operation from group
		operation := buildOperation(key, group, staticPresent, excludedOrigins)

		s := slot{key.path, key.method}
		if winner, collided := occupiedSlots[s]; collided {
			// SEC-BE-001/SEC-BE-002: two groups (distinct origins)
			// normalized to the same (path, method) slot; only one
			// Operation fits in doc.Paths. The caller's sort guarantees
			// `winner` is the lowest-trustRank (most trusted) group — this
			// later group must not clobber it. The loss is made visible on
			// the winning operation (same style as x-vespasian-source)
			// rather than silently discarded.
			recordCollisionOrigin(winner, key.origin)
			continue
		}
		occupiedSlots[s] = operation

		pathItem := doc.Paths.Find(key.path)
		if pathItem == nil {
			pathItem = &openapi3.PathItem{}
			doc.Paths.Set(key.path, pathItem)
		}

		// Set operation for the method
		switch key.method {
		case "get":
			pathItem.Get = operation
		case "post":
			pathItem.Post = operation
		case "put":
			pathItem.Put = operation
		case "delete":
			pathItem.Delete = operation
		case "patch":
			pathItem.Patch = operation
		case "head":
			pathItem.Head = operation
		case "options":
			pathItem.Options = operation
		}
	}
}

// Generate produces an OpenAPI specification.
func (g *OpenAPIGenerator) Generate(endpoints []classify.ClassifiedRequest) ([]byte, error) {
	if len(endpoints) == 0 {
		return nil, nil
	}

	// Extract servers and title
	servers, titleHost, excludedOrigins := extractServers(endpoints, g.TargetOrigin)

	// Create OpenAPI document
	doc := &openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   titleHost,
			Version: "1.0.0",
		},
		Paths:   openapi3.NewPaths(),
		Servers: servers,
	}

	// Group and sort endpoints
	endpointGroups := groupEndpoints(endpoints, NormalizeOptions{MergeSlugs: g.MergeSlugs, SlugThreshold: g.SlugThreshold})

	// Determine whether to emit x-vespasian-source extensions.
	// Only emitted when at least one input request has a "static:" Source so that
	// output is byte-identical to pre-LAB-2108 when --analyze-js is not in use.
	staticPresent := anyStaticSource(endpoints)

	// primaryOrigin is the origin extractServers placed at servers[0] (the
	// vouched TargetOrigin if usable, else the lowest-sorted dynamically
	// observed origin, else "" when the run cannot vouch for anything). Fed
	// into trustRank below so the (path, method) slot collision resolves to
	// the most trusted colliding origin, never to whichever origin's
	// hostname happens to sort first alphabetically.
	primaryOrigin := ""
	if len(servers) > 0 {
		primaryOrigin = servers[0].URL
	}

	// Sort endpoint keys for deterministic output. SEC-BE-001: origin is now
	// part of endpointKey, so two groups can share a (path, method) slot in
	// doc.Paths (only one can occupy it — see resolveCollisions). The
	// lowest-trustRank origin sorts first for a shared (path, method) — see
	// trustRank's doc comment for why rank, not a primary/non-primary
	// boolean, is required — and the trailing origin-string compare exists
	// only to keep the sort a strict total order (LAB-4678's determinism
	// guarantee) among keys that share the same rank.
	keys := make([]endpointKey, 0, len(endpointGroups))
	for k := range endpointGroups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path != keys[j].path {
			return keys[i].path < keys[j].path
		}
		if keys[i].method != keys[j].method {
			return keys[i].method < keys[j].method
		}
		ri := trustRank(keys[i].origin, primaryOrigin, excludedOrigins)
		rj := trustRank(keys[j].origin, primaryOrigin, excludedOrigins)
		if ri != rj {
			return ri < rj
		}
		return keys[i].origin < keys[j].origin
	})

	resolveCollisions(doc, keys, endpointGroups, staticPresent, excludedOrigins)

	// Extract schemas to components/schemas with $ref references
	extractComponents(doc)

	// Validate the spec
	specBytes, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}

	loader := openapi3.NewLoader()
	_, err = loader.LoadFromData(specBytes)
	if err != nil {
		return nil, err
	}

	// Serialize based on format
	format := g.Format
	if format == "" {
		format = "yaml"
	}

	if format == "json" {
		return json.MarshalIndent(doc, "", "  ")
	}

	// Reuse the already-serialized YAML from validation
	return specBytes, nil
}

// extractPathParams extracts parameter names from a path template like "/users/{userId}/posts/{postId}".
func extractPathParams(path string) []string {
	var params []string
	segments := strings.Split(path, "/")
	for _, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			paramName := strings.TrimPrefix(strings.TrimSuffix(segment, "}"), "{")
			params = append(params, paramName)
		}
	}
	return params
}

// commonPathExtensions are file extensions often seen in web app URLs that should
// not form part of an OpenAPI component name (they're not resource names, they're
// server-side file types).
var commonPathExtensions = map[string]bool{
	".php": true, ".asp": true, ".aspx": true, ".jsp": true, ".mvc": true,
	".html": true, ".htm": true, ".json": true, ".xml": true, ".action": true, ".do": true,
}

// resourceNameFromPath extracts and capitalizes the resource name from an API path.
// It returns the last non-parameterized, non-empty segment as a singular, capitalized word.
// Examples:
//   - "/api/v2/tickets" → "Ticket"
//   - "/api/v2/tickets/{ticketId}" → "Ticket"
//   - "/api/v2/categories/{categoryId}/items/{itemId}" → "Item"
//   - "/api/v2/users/me/settings" → "Setting"
//   - "/login.php" → "Login"
//   - "/stored-xss" → "StoredXss"
func resourceNameFromPath(path string) string {
	segments := strings.Split(path, "/")
	// Walk backwards to find last non-param, non-empty segment
	for i := len(segments) - 1; i >= 0; i-- {
		seg := segments[i]
		if seg == "" || strings.HasPrefix(seg, "{") {
			continue
		}
		return sanitizeResourceName(seg)
	}
	return "Resource"
}

// toCamelCase converts a string to CamelCase by splitting on non-alphanumeric
// characters and capitalizing the first letter of each resulting segment.
//
// Note: this function is ASCII-only by design. Non-ASCII letters (e.g., 'é',
// 'ñ', '日本語') fall through to the separator branch and are dropped from the
// output. OpenAPI component names are conventionally ASCII; if a path segment
// is entirely non-ASCII the result will be empty and resourceNameFromPath
// falls back to "Resource".
func toCamelCase(s string) string {
	var b strings.Builder
	capitalizeNext := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			if capitalizeNext {
				r = r - 'a' + 'A'
			}
			b.WriteRune(r)
			capitalizeNext = false
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			capitalizeNext = false
		default:
			capitalizeNext = true
		}
	}
	return b.String()
}

// sanitizeResourceName turns a path segment into a valid OpenAPI component name
// fragment: strips common file extensions, splits on non-alphanumerics, capitalizes
// and joins each part, then singularizes. Falls back to "Resource" if the segment
// sanitizes to empty.
func sanitizeResourceName(seg string) string {
	lower := strings.ToLower(seg)
	for ext := range commonPathExtensions {
		if strings.HasSuffix(lower, ext) {
			seg = seg[:len(seg)-len(ext)]
			break
		}
	}
	result := toCamelCase(seg)
	if result == "" {
		return "Resource"
	}
	if result[0] >= '0' && result[0] <= '9' {
		return "Resource" + result
	}
	return singularize(result)
}

// schemaFingerprint computes a string fingerprint of a schema for deduplication.
// Returns a sorted, comma-separated list of "propertyName:type" pairs.
func schemaFingerprint(schema *openapi3.Schema) string {
	if schema == nil || schema.Properties == nil {
		return ""
	}
	keys := make([]string, 0, len(schema.Properties))
	for k, v := range schema.Properties {
		t := "unknown"
		if v != nil && v.Value != nil && v.Value.Type != nil && len(v.Value.Type.Slice()) > 0 {
			t = v.Value.Type.Slice()[0]
		}
		keys = append(keys, k+":"+t)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// extractComponents extracts inline schemas to components/schemas with $ref references.
// This is called after all paths are built, before validation.
func extractComponents(doc *openapi3.T) { //nolint:gocyclo // component extraction logic
	// Initialize components if needed
	if doc.Components == nil {
		doc.Components = &openapi3.Components{}
	}
	if doc.Components.Schemas == nil {
		doc.Components.Schemas = make(openapi3.Schemas)
	}

	// Separate fingerprint→name maps for request and response so an echo-style
	// endpoint where the request and response bodies share the same property
	// shape doesn't cause the response to reuse the request's component name
	// (e.g., a response getting tagged `CreateUserRequest`).
	fingerprintToReqName := make(map[string]string)
	fingerprintToRespName := make(map[string]string)
	// Track name collisions — shared across both maps so we never generate
	// two components with the same name (e.g., UserResponse collision).
	nameCounter := make(map[string]int)

	// Helper to ensure unique component name
	ensureUniqueName := func(baseName string) string {
		nameCounter[baseName]++
		if nameCounter[baseName] == 1 {
			return baseName
		}
		return baseName + strconv.Itoa(nameCounter[baseName])
	}

	// Helper to derive status code context for response names
	statusContext := func(statusCode string) string {
		switch statusCode {
		case "200":
			return "Response"
		case "201":
			return "CreatedResponse"
		case "204":
			return "" // No body for 204
		case "400":
			return "BadRequestResponse"
		case "401":
			return "UnauthorizedResponse"
		case "403":
			return "ForbiddenResponse"
		case "404":
			return "NotFoundResponse"
		case "500":
			return "InternalErrorResponse"
		default:
			return statusCode + "Response"
		}
	}

	// Walk all paths and operations in deterministic order so that when multiple
	// paths share a schema fingerprint, the component name (chosen on first encounter)
	// is stable across runs.
	pathsMap := doc.Paths.Map()
	sortedPaths := make([]string, 0, len(pathsMap))
	for p := range pathsMap {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)
	for _, path := range sortedPaths {
		pathItem := doc.Paths.Find(path)
		if pathItem == nil {
			continue
		}

		resourceName := resourceNameFromPath(path)

		operations := []*struct {
			method    string
			operation *openapi3.Operation
		}{
			{"post", pathItem.Post},
			{"put", pathItem.Put},
			{"patch", pathItem.Patch},
			{"get", pathItem.Get},
			{"delete", pathItem.Delete},
			{"head", pathItem.Head},
			{"options", pathItem.Options},
		}

		for _, op := range operations {
			if op.operation == nil {
				continue
			}

			// Extract request body schema
			if op.operation.RequestBody != nil && op.operation.RequestBody.Value != nil {
				reqBody := op.operation.RequestBody.Value
				ctKeys := make([]string, 0, len(reqBody.Content))
				for k := range reqBody.Content {
					ctKeys = append(ctKeys, k)
				}
				sort.Strings(ctKeys)
				for _, ctKey := range ctKeys {
					mediaType := reqBody.Content[ctKey]
					if mediaType == nil || mediaType.Schema == nil {
						continue
					}
					if schema := mediaType.Schema.Value; schema != nil && schema.Properties != nil {
						fingerprint := schemaFingerprint(schema)
						if fingerprint != "" {
							var componentName string
							if existingName, exists := fingerprintToReqName[fingerprint]; exists {
								// Reuse existing request component
								componentName = existingName
							} else {
								// Create new request component
								methodPrefix := ""
								switch op.method {
								case "post":
									methodPrefix = "Create"
								case "put", "patch":
									methodPrefix = "Update"
								}
								baseName := methodPrefix + resourceName + "Request"
								componentName = ensureUniqueName(baseName)
								doc.Components.Schemas[componentName] = &openapi3.SchemaRef{Value: schema}
								fingerprintToReqName[fingerprint] = componentName
							}
							// Replace inline schema with $ref
							mediaType.Schema = &openapi3.SchemaRef{
								Ref: "#/components/schemas/" + componentName,
							}
						}
					}
				}
			}

			// Extract response schemas
			if op.operation.Responses != nil {
				sortedStatusCodes := make([]string, 0, op.operation.Responses.Len())
				for statusCode := range op.operation.Responses.Map() {
					sortedStatusCodes = append(sortedStatusCodes, statusCode)
				}
				sort.Strings(sortedStatusCodes)
				for _, statusCode := range sortedStatusCodes {
					respRef := op.operation.Responses.Value(statusCode)
					if respRef == nil || respRef.Value == nil {
						continue
					}
					response := respRef.Value
					respCtKeys := make([]string, 0, len(response.Content))
					for k := range response.Content {
						respCtKeys = append(respCtKeys, k)
					}
					sort.Strings(respCtKeys)
					for _, respCtKey := range respCtKeys {
						mediaType := response.Content[respCtKey]
						if mediaType == nil || mediaType.Schema == nil {
							continue
						}
						if schema := mediaType.Schema.Value; schema != nil && schema.Properties != nil {
							fingerprint := schemaFingerprint(schema)
							if fingerprint != "" {
								var componentName string
								if existingName, exists := fingerprintToRespName[fingerprint]; exists {
									// Reuse existing response component
									componentName = existingName
								} else {
									// Create new response component
									suffix := statusContext(statusCode)
									if suffix == "" {
										continue // Skip 204 No Content
									}
									baseName := resourceName + suffix
									componentName = ensureUniqueName(baseName)
									doc.Components.Schemas[componentName] = &openapi3.SchemaRef{Value: schema}
									fingerprintToRespName[fingerprint] = componentName
								}
								// Replace inline schema with $ref
								mediaType.Schema = &openapi3.SchemaRef{
									Ref: "#/components/schemas/" + componentName,
								}
							}
						}
					}
				}
			}
		}
	}

	// Remove empty components section
	if len(doc.Components.Schemas) == 0 {
		doc.Components = nil
	}
}

// DefaultExtension returns the default file extension.
func (g *OpenAPIGenerator) DefaultExtension() string {
	return ".yaml"
}
