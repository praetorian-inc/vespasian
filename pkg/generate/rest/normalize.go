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
	"regexp"
	"strconv"
	"strings"
)

// paramKind classifies a path segment that has been identified as a dynamic
// parameter. The kind drives the suffix used when deriving a parameter name
// from context (e.g., users/{userId} for IDs, articles/{articleSlug} for slugs).
type paramKind int

const (
	kindLiteral paramKind = iota
	kindUUID
	kindObjectID
	kindNumeric
	kindShortHex
	kindBase64
	kindSlug // assigned only by observation-based detection
)

var (
	// uuidRegex matches UUIDs in paths (8-4-4-4-12 format).
	uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// numericRegex matches purely numeric segments.
	numericRegex = regexp.MustCompile(`^[0-9]+$`)
	// objectIDRegex matches MongoDB ObjectIDs: exactly 24 hex characters.
	// Hex strings of intermediate length (13-23 characters) are intentionally
	// not classified as a parameter kind by the regex pass — they are
	// uncommon as identifiers in real APIs. If observed varying across paths
	// they will still be promoted by observation-based detection in
	// NormalizePathsWithNames.
	objectIDRegex = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	// shortHexRegex matches short hex hashes: 6-12 hex characters.
	// Pure-numeric strings are excluded by the caller so they classify as kindNumeric instead.
	// The caller (isShortHexHash) additionally requires at least one digit or
	// uppercase letter to avoid matching pure-lowercase English words that
	// happen to consist of [a-f] characters (e.g., "facade", "decade").
	shortHexRegex = regexp.MustCompile(`^[0-9a-fA-F]{6,12}$`)
	// base64Regex matches base64 / base64url tokens that are at least 16
	// characters long. The base64 character set is constrained to URL-safe
	// characters; standard base64 may also include `+` and `/`, both of which
	// are valid in path segments after percent-decoding.
	base64Regex = regexp.MustCompile(`^[A-Za-z0-9_\-+/]{16,}={0,2}$`)
	// versionPrefixRegex matches "v" followed by digits, requiring the
	// leading digit to be non-zero — `v1`, `v2`, `v123` qualify but
	// `v0`, `v01`, `v001` do not (none of those are conventional REST
	// version markers).
	//
	// Design note on `v0`: a small number of APIs do publish under
	// `/v0/...` for alpha or pre-release surfaces. We deliberately keep
	// `v0` OUT of the scaffold set so that paths like `/v0/users/<varying>`
	// participate in observation-based promotion rather than being treated
	// as protected resource scaffold. If a future maintainer is tempted to
	// relax this regex to `^v[0-9]+$`, note that doing so will suppress
	// promotion of resource-type segments under `/v0/...` and require new
	// regression tests to lock in the desired behavior.
	versionPrefixRegex = regexp.MustCompile(`^v[1-9][0-9]*$`)
)

// knownLiterals are exact path segment values that must be preserved as
// literals even if their text would otherwise match a dynamic-segment regex.
// These are conventional REST literals for "self-relative" or action-style
// endpoints (e.g., `/users/me`, `/items/search`).
var knownLiterals = map[string]struct{}{
	"me":      {},
	"current": {},
	"self":    {},
	"new":     {},
	"list":    {},
	"search":  {},
}

// pathPrefixes are scaffold segments that wrap an API surface but do not
// themselves identify a resource. When an observed path looks like
// `/api/users` or `/v1/posts`, the leading scaffold should not count as the
// "resource type" preceding a parameter — otherwise observation-based
// detection would conflate distinct resource types (`users`, `posts`) into a
// single varying parameter.
var pathPrefixes = map[string]struct{}{
	"api":  {},
	"apis": {},
	"rest": {},
}

// isPathPrefix reports whether a literal segment is a known API scaffold
// (api / rest / version segments like v1, v2). isObservationCandidate uses
// this to skip paths whose only preceding literal context is a scaffold —
// the segment immediately following such a scaffold is the resource type
// and must not be parameterized.
func isPathPrefix(segment string) bool {
	if _, ok := pathPrefixes[segment]; ok {
		return true
	}
	return versionPrefixRegex.MatchString(segment)
}

// isShortHexHash reports whether a segment looks like a short hex hash
// (e.g., a git short-SHA `a1b2c3d4`). It requires the regex match plus at
// least one digit or uppercase A-F so that pure-lowercase English words
// composed of [a-f] characters (e.g., "facade", "decade", "beaded") are
// not misclassified as hashes.
//
// Trade-off: all-uppercase hex words (e.g., "FACADE", "DECADE") still
// classify as hashes because their uppercase A-F characters satisfy the
// discriminator. URL path segments are almost never all-uppercase English
// words, so this edge case is accepted in exchange for catching real
// uppercase short-SHAs like "ABCDEF".
func isShortHexHash(segment string) bool {
	if !shortHexRegex.MatchString(segment) {
		return false
	}
	for _, r := range segment {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') {
			return true
		}
	}
	return false
}

// classifyParamSegment determines whether a path segment is a dynamic-parameter
// candidate based on its text alone. It returns kindLiteral for empty
// segments, known literals, and any segment whose shape does not match a
// known dynamic pattern. Callers that have a population of paths can promote
// kindLiteral results to kindSlug via observation-based detection.
func classifyParamSegment(segment string) paramKind {
	if segment == "" {
		return kindLiteral
	}
	if _, ok := knownLiterals[segment]; ok {
		return kindLiteral
	}
	switch {
	case uuidRegex.MatchString(segment):
		return kindUUID
	case objectIDRegex.MatchString(segment):
		return kindObjectID
	case numericRegex.MatchString(segment):
		return kindNumeric
	case isShortHexHash(segment):
		return kindShortHex
	case isBase64Token(segment):
		return kindBase64
	}
	return kindLiteral
}

// isBase64Token returns true when segment looks like an opaque base64 token.
// A base64 token mixes character classes (alpha + digit, or includes the
// base64-specific punctuation `+`/`/`/`=`). This guard prevents long
// lower-case slugs (e.g., `the-best-blog-post-ever`) from classifying as
// base64.
//
// Trade-off: an all-uppercase base64-shaped token without `+`/`/`/`=`
// punctuation (e.g., `ABCDEF0123456789XY`) returns false and falls
// through to kindLiteral. This is the symmetric cost of requiring mixed
// case + digit to reject all-lowercase slugs; it is asymmetric with
// isShortHexHash, which DOES accept all-uppercase hex strings (because
// short-SHA refs are commonly uppercased while base64 tokens are not).
// All-uppercase base64 in URL path positions is rare; if encountered, the
// observation-based pass in NormalizePathsWithNames will still detect it
// as a slug given enough varying observations.
func isBase64Token(segment string) bool {
	if !base64Regex.MatchString(segment) {
		return false
	}
	if strings.ContainsAny(segment, "+/=") {
		return true
	}
	hasUpper := strings.ContainsFunc(segment, func(r rune) bool { return r >= 'A' && r <= 'Z' })
	hasLower := strings.ContainsFunc(segment, func(r rune) bool { return r >= 'a' && r <= 'z' })
	hasDigit := strings.ContainsFunc(segment, func(r rune) bool { return r >= '0' && r <= '9' })
	// Require a mix of letter cases with digits when no base64-specific
	// punctuation is present. A pure lowercase + digit string with hyphens
	// looks like a slug, not a token.
	return hasUpper && hasLower && hasDigit
}

// NormalizePath normalizes a URL path for OpenAPI specification.
// It replaces dynamic path segments (UUIDs, MongoDB ObjectIDs, numeric IDs,
// short hex hashes, base64 tokens) with `{id}` placeholders. Known
// literal segments (e.g., `me`, `current`) are preserved.
// Kept for backward compatibility.
func NormalizePath(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment == "" {
			continue
		}
		if classifyParamSegment(segment) != kindLiteral {
			segments[i] = "{id}"
		}
	}
	return strings.Join(segments, "/")
}

// NormalizePathWithNames normalizes a URL path with context-aware parameter
// names based on the preceding path segment. It detects UUIDs, MongoDB
// ObjectIDs, numeric IDs, short hex hashes, and base64 tokens.
//
// Examples:
//
//   - /users/42                                    -> /users/{userId}
//   - /posts/5/comments/7                          -> /posts/{postId}/comments/{commentId}
//   - /articles/507f1f77bcf86cd799439011           -> /articles/{articleId}   (MongoDB ObjectID)
//   - /commits/a1b2c3d4                            -> /commits/{commitId}     (short hex)
//   - /sessions/AbCdEfGhIj1234567890XY             -> /sessions/{sessionToken} (base64)
//   - /users/me                                    -> /users/me               (literal preserved)
//
// For slug-style identifiers that vary across observed paths, use
// NormalizePathsWithNames which performs observation-based detection.
//
// This function remains exported as a single-path utility for callers that
// only have one path to normalize and intentionally do not need slug
// detection (e.g., ad-hoc tooling, debug utilities, simple migrations). The
// production OpenAPI generation pipeline does not call this function — it
// uses NormalizePathsWithNames so observation-based detection can fire
// across the full population. New code with access to a population of
// paths should prefer NormalizePathsWithNames.
func NormalizePathWithNames(path string) string {
	segments := strings.Split(path, "/")
	kinds := make([]paramKind, len(segments))
	for i, segment := range segments {
		kinds[i] = classifyParamSegment(segment)
	}
	applyKindsToSegments(segments, kinds)
	deduplicateParamNames(segments)
	return strings.Join(segments, "/")
}

// pathInfo holds a single path split into segments along with the
// classification of each segment.
type pathInfo struct {
	segments []string
	kinds    []paramKind
}

// posKey uniquely identifies a path position across observations: same
// surrounding shape and same path length collapse into the same bucket.
type posKey struct {
	prefix string
	index  int
	suffix string
	length int
}

// segLoc is a (path, segment) coordinate used by promoteVaryingPositions
// and unifyMixedKindsAtSamePosition to record which segments need to be
// rewritten in a separate pass.
type segLoc struct {
	pathIdx, segIdx int
}

// NormalizePathsWithNames classifies each input path's segments by regex /
// literal kind, then performs observation-based detection: a position whose
// literal segment value varies across paths sharing the same prefix and
// suffix shape (and same path length) is promoted to a slug-style
// parameter. Promotion runs to a fixed point — promoting one position can
// change the shape of a sibling position, exposing additional varying
// buckets — so the function iterates until no further promotions occur.
//
// Returns a map keyed by the original input path. When the same path appears
// multiple times the map collapses to a single normalized entry, which is
// the desired behavior for grouping observed endpoints.
//
// Limitation: detection requires at least two literal observations sharing
// both prefix and suffix shape. Pure-diagonal observations such as
// `[/repos/alice/proj1, /repos/bob/proj2, /repos/carol/proj3]` — where every
// (owner, project) pair is unique — cannot be promoted, because each
// position's bucket is a singleton. Add overlapping observations (e.g.,
// `/repos/alice/proj1` together with `/repos/alice/proj2` and
// `/repos/bob/proj1`) to anchor the inference.
//
// Saturation behavior: if the maxPromotionRounds cap fires (see SEC-BE-001
// note below), any segments that did not converge to kindSlug remain
// kindLiteral and pass through unchanged in the returned map. The function
// has no error channel and does not signal cap saturation to the caller
// today; downstream consumers receive a partially-normalized result. A
// debug logging hook for cap-saturation events is a reasonable future
// addition but is not in scope for LAB-2107.
func NormalizePathsWithNames(paths []string) map[string]string {
	if len(paths) == 0 {
		return map[string]string{}
	}

	infos := classifyPaths(paths)
	for i := 0; i < maxPromotionRounds; i++ {
		varying := findVaryingPositions(infos)
		if len(varying) == 0 {
			break
		}
		// Defensive guard: if findVaryingPositions returned a non-empty
		// set, promoteVaryingPositions is expected to convert at least one
		// segment (the find phase only surfaces literal candidates).
		// promoteVaryingPositions returning false here would indicate an
		// internal contract break; we exit the loop safely rather than
		// spin.
		if !promoteVaryingPositions(infos, varying) {
			break
		}
	}
	unifyMixedKindsAtSamePosition(infos)
	return renderNormalizedPaths(paths, infos)
}

// maxPromotionRounds bounds the fixed-point iteration in
// NormalizePathsWithNames. Each round can only convert kindLiteral to
// kindSlug (monotonic), so termination is guaranteed by the size of the
// literal set; under realistic API captures fewer than five rounds are
// required. The cap protects against pathological inputs (deeply-nested
// adversarial paths) where the loop could otherwise reach O(S) iterations
// and produce an O(N*S^3) CPU-DoS surface at the generate step. After the
// cap, any remaining unpromoted segments stay literal — best-effort
// detection — and unifyMixedKindsAtSamePosition still runs on whatever
// kinds are present. See SEC-BE-001 in the LAB-2107 review history.
//
// This is a `var` (not a `const`) so tests can lower it with t.Setenv-style
// save/restore to verify the saturation contract under controlled
// conditions. Production code MUST NOT mutate this value.
var maxPromotionRounds = 8

// unifyMixedKindsAtSamePosition collapses regex-classified kinds onto
// kindSlug when an observation-promoted slug shares the same shape position
// in another path. Without this pass, /articles/my-first-post,
// /articles/507f1f77bcf86cd799439011, and /articles/another-post would
// produce two distinct OpenAPI path templates — /articles/{articleSlug}
// for the slug observations and /articles/{articleId} for the ObjectID —
// even though they describe the same parameterized endpoint. Whenever a
// position has been promoted to kindSlug for any path, any other path
// whose segment at the same position is a different non-literal kind
// (UUID, ObjectID, numeric, short hex, base64) is unified onto kindSlug
// so a single template emerges. Literal segments are not touched.
func unifyMixedKindsAtSamePosition(infos []pathInfo) {
	groups := make(map[posKey][]segLoc)
	hasSlug := make(map[posKey]bool)
	hasOther := make(map[posKey]bool)
	for pIdx := range infos {
		info := &infos[pIdx]
		for sIdx, k := range info.kinds {
			if k == kindLiteral {
				continue
			}
			key := positionKey(*info, sIdx)
			groups[key] = append(groups[key], segLoc{pIdx, sIdx})
			if k == kindSlug {
				hasSlug[key] = true
			} else {
				hasOther[key] = true
			}
		}
	}
	// Map iteration order is non-deterministic in Go, but the inner
	// assignment (kinds[i] = kindSlug) is idempotent and reaches a single
	// fixed final state. The observable output of NormalizePathsWithNames is
	// therefore deterministic regardless of which order keys are visited.
	// Adding any order-sensitive operation here would break that invariant.
	for key, locs := range groups {
		if !hasSlug[key] || !hasOther[key] {
			continue
		}
		for _, l := range locs {
			if infos[l.pathIdx].kinds[l.segIdx] != kindSlug {
				infos[l.pathIdx].kinds[l.segIdx] = kindSlug
			}
		}
	}
}

// classifyPaths splits each input path and classifies each segment by its
// regex / literal kind.
func classifyPaths(paths []string) []pathInfo {
	infos := make([]pathInfo, len(paths))
	for i, p := range paths {
		segs := strings.Split(p, "/")
		kinds := make([]paramKind, len(segs))
		for j, s := range segs {
			kinds[j] = classifyParamSegment(s)
		}
		infos[i] = pathInfo{segments: segs, kinds: kinds}
	}
	return infos
}

// findVaryingPositions returns the set of position buckets whose literal
// segments vary across observations and therefore qualify for slug-style
// parameter promotion.
func findVaryingPositions(infos []pathInfo) map[posKey]struct{} {
	values := make(map[posKey]map[string]struct{})
	for _, info := range infos {
		for i, seg := range info.segments {
			if !isObservationCandidate(info, i, seg) {
				continue
			}
			key := positionKey(info, i)
			set, ok := values[key]
			if !ok {
				set = make(map[string]struct{})
				values[key] = set
			}
			set[seg] = struct{}{}
		}
	}
	varying := make(map[posKey]struct{})
	for key, set := range values {
		if len(set) >= 2 {
			varying[key] = struct{}{}
		}
	}
	return varying
}

// promoteVaryingPositions rewrites the kind of each segment that lies in a
// varying position bucket from kindLiteral to kindSlug. Returns true when at
// least one segment was promoted, so callers can break out of fixed-point
// iteration loops without performing redundant work.
//
// Caller contract: `varying` is non-empty. The sole caller in this package
// (NormalizePathsWithNames) only reaches this function with a non-empty
// varying set; we therefore do not include a defensive `len(varying)==0`
// short-circuit.
//
// Promotions are computed against an immutable snapshot of `kinds`, then
// applied in a second pass. Mutating `kinds` while iterating would change
// the shape used to compute positionKey for subsequent positions in the
// same path — producing keys that no longer match `varying` and silently
// suppressing promotion of those positions in this round. The atomic
// two-pass strategy ensures every position eligible at the start of the
// round is promoted at the end of the round, giving the outer fixed-point
// loop a clean view of the next round's candidate set.
func promoteVaryingPositions(infos []pathInfo, varying map[posKey]struct{}) bool {
	// len(infos) is the number of paths and is a reasonable upper-bound
	// hint for typical API captures (a single promotion per path is
	// common); the slice grows beyond if more positions promote per path.
	toPromote := make([]segLoc, 0, len(infos))
	for idx := range infos {
		info := &infos[idx]
		for i, seg := range info.segments {
			if !isObservationCandidate(*info, i, seg) {
				continue
			}
			if _, ok := varying[positionKey(*info, i)]; !ok {
				continue
			}
			if info.kinds[i] != kindSlug {
				toPromote = append(toPromote, segLoc{idx, i})
			}
		}
	}
	if len(toPromote) == 0 {
		return false
	}
	for _, l := range toPromote {
		infos[l.pathIdx].kinds[l.segIdx] = kindSlug
	}
	return true
}

// renderNormalizedPaths produces the final map of input paths to normalized
// paths. Duplicate input paths collapse to a single entry.
func renderNormalizedPaths(paths []string, infos []pathInfo) map[string]string {
	out := make(map[string]string, len(paths))
	for i, p := range paths {
		if _, done := out[p]; done {
			continue
		}
		segments := append([]string(nil), infos[i].segments...)
		applyKindsToSegments(segments, infos[i].kinds)
		deduplicateParamNames(segments)
		out[p] = strings.Join(segments, "/")
	}
	return out
}

// isObservationCandidate reports whether segment i of info is eligible for
// observation-based slug promotion. Empty segments, non-literal segments,
// known literals, and the very first non-empty literal of a path are all
// excluded.
func isObservationCandidate(info pathInfo, i int, seg string) bool {
	if seg == "" || info.kinds[i] != kindLiteral {
		return false
	}
	if _, ok := knownLiterals[seg]; ok {
		return false
	}
	return hasLiteralContext(info.segments[:i], info.kinds[:i])
}

// positionKey computes the bucket key for the segment at index i of info.
func positionKey(info pathInfo, i int) posKey {
	return posKey{
		prefix: shapeKey(info.segments[:i], info.kinds[:i]),
		index:  i,
		suffix: shapeKey(info.segments[i+1:], info.kinds[i+1:]),
		length: len(info.segments),
	}
}

// hasLiteralContext reports whether a path slice contains at least one
// non-empty literal segment that is NOT a known API scaffold (`api`, `rest`,
// or a `v\d+` version marker). Observation-based detection requires this so
// that the very first resource segment of a path — including paths that
// start with a scaffold like `/api/users` or `/v1/users` — cannot be
// promoted to a parameter. The scaffold by itself is not enough context to
// identify the next segment as a parameter rather than a resource type.
func hasLiteralContext(segments []string, kinds []paramKind) bool {
	for i, s := range segments {
		if s == "" {
			continue
		}
		if kinds[i] != kindLiteral {
			continue
		}
		if isPathPrefix(s) {
			continue
		}
		return true
	}
	return false
}

// shapeKey produces a normalized "shape" representation of a path slice that
// collapses any already-classified parameter to a single placeholder. This
// allows two paths with different parameter names but the same structural
// shape to share an observation-bucket.
func shapeKey(segments []string, kinds []paramKind) string {
	parts := make([]string, len(segments))
	for i, s := range segments {
		switch kinds[i] {
		case kindLiteral:
			parts[i] = s
		default:
			parts[i] = "{}"
		}
	}
	return strings.Join(parts, "/")
}

// applyKindsToSegments rewrites segments in place: any non-literal kind is
// replaced with `{<contextName>}` derived from the preceding non-empty,
// non-parameterized segment.
//
// Mutation safety: this loop walks left-to-right and rewrites segments[i]
// before computing contextualParamName for i+1. The backwards walk in
// contextualParamName looks for the nearest preceding *literal* segment
// (kinds[j] == kindLiteral). When a previous index j was rewritten in this
// loop, kinds[j] is non-literal, so the backwards walk skips j and reads
// only segments whose value has NOT been touched. The in-place strategy
// is therefore safe — no snapshot is required — and matches the cheaper
// single-pass design of NormalizePathWithNames.
//
// promoteVaryingPositions has a different invariant (it computes posKey
// from segments + kinds for SUBSEQUENT positions in the same path, not
// preceding ones) and therefore uses a two-pass strategy. Do not assume
// the patterns are interchangeable.
func applyKindsToSegments(segments []string, kinds []paramKind) {
	for i := range segments {
		if kinds[i] == kindLiteral {
			continue
		}
		paramName := contextualParamName(segments, kinds, i)
		segments[i] = "{" + paramName + "}"
	}
}

// contextualParamName returns the parameter name for the segment at index i,
// based on the nearest preceding literal segment and the kind of the segment.
func contextualParamName(segments []string, kinds []paramKind, i int) string {
	prev := ""
	for j := i - 1; j >= 0; j-- {
		if segments[j] == "" {
			continue
		}
		if kinds[j] == kindLiteral {
			prev = segments[j]
			break
		}
	}
	return paramNameFromKind(prev, kinds[i])
}

// deduplicateParamNames ensures unique parameter names within a path.
// Repeated names get a numeric suffix: {id}, {id2}, {id3}, ...
func deduplicateParamNames(segments []string) {
	seen := make(map[string]int)
	for i, segment := range segments {
		if !strings.HasPrefix(segment, "{") || !strings.HasSuffix(segment, "}") {
			continue
		}
		name := segment[1 : len(segment)-1]
		seen[name]++
		if seen[name] > 1 {
			segments[i] = "{" + name + strconv.Itoa(seen[name]) + "}"
		}
	}
}

// sanitizeParamName produces an OpenAPI-friendly parameter name.
//
// Allowed characters: alphanumeric and underscore. Hyphens and dots are
// converted to camelCase boundaries: the next ASCII lowercase letter after
// a `-` or `.` is uppercased, and the separator is dropped. Other
// characters are dropped silently. An empty result becomes "id".
//
// This makes parameter names compatible with the wide majority of OpenAPI
// client generators, many of which treat hyphens/dots as invalid identifier
// characters or as word separators that produce unusable accessors. For
// example, the context segment `my-service` yields the suffix `myService`
// rather than `my-service`.
//
// Precondition: callers in this package only invoke sanitizeParamName with
// the output of singularize(prevSegment) appended to a kind-suffix (`Id`,
// `Token`, `Slug`). prevSegment is a URL path literal, so it cannot start
// with `-` or `.`. If a future caller passes input beginning with a
// separator, the first surviving lowercase letter will be uppercased and
// emit a PascalCase-first name (e.g., `-user` → `User`). The function does
// not validate the precondition; uphold it at the call site.
func sanitizeParamName(name string) string {
	var b strings.Builder
	upperNext := false
	for _, r := range name {
		switch {
		case r == '-' || r == '.':
			upperNext = true
		case r >= 'a' && r <= 'z':
			if upperNext {
				b.WriteRune(r - ('a' - 'A'))
			} else {
				b.WriteRune(r)
			}
			upperNext = false
		case r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_':
			b.WriteRune(r)
			upperNext = false
		default:
			// Drop disallowed characters silently.
		}
	}
	if b.Len() == 0 {
		return "id"
	}
	return b.String()
}

// paramNameFromKind derives a parameter name from a path segment and the kind
// of the parameter being named. ID-style kinds use the `Id` suffix; base64
// tokens use `Token`; slugs use `Slug`. An empty preceding segment yields
// the bare suffix in lowercase form (`id`, `token`, `slug`).
func paramNameFromKind(prevSegment string, kind paramKind) string {
	suffix := suffixForKind(kind)
	if prevSegment == "" {
		return strings.ToLower(suffix)
	}
	singular := singularize(prevSegment)
	return sanitizeParamName(singular + suffix)
}

// suffixForKind returns the parameter name suffix associated with a paramKind:
// "Token" for base64 tokens, "Slug" for observation-promoted slugs, "Id" for
// every other identifier-shaped kind (UUID, ObjectID, numeric, short hex).
func suffixForKind(kind paramKind) string {
	switch kind {
	case kindBase64:
		return "Token"
	case kindSlug:
		return "Slug"
	default:
		return "Id"
	}
}

// singularize converts a plural word to singular (naive implementation).
// Rules:
//   - "ies" -> "y" (categories -> category)
//   - "sses" -> "ss" (addresses -> address)
//   - "s" -> "" (users -> user)
//   - otherwise -> return as-is (data -> data)
func singularize(word string) string {
	if strings.HasSuffix(word, "ies") {
		return strings.TrimSuffix(word, "ies") + "y"
	}
	if strings.HasSuffix(word, "sses") {
		return strings.TrimSuffix(word, "sses") + "ss"
	}
	if strings.HasSuffix(word, "s") && !strings.HasSuffix(word, "ss") {
		return strings.TrimSuffix(word, "s")
	}
	return word
}
