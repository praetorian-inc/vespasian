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
	objectIDRegex = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	// shortHexRegex matches short hex hashes: 6-12 hex characters.
	// Pure-numeric strings are excluded by the caller so they classify as kindNumeric instead.
	shortHexRegex = regexp.MustCompile(`^[0-9a-fA-F]{6,12}$`)
	// base64Regex matches base64 / base64url tokens that are at least 16
	// characters long. The base64 character set is constrained to URL-safe
	// characters; standard base64 may also include `+` and `/`, both of which
	// are valid in path segments after percent-decoding.
	base64Regex = regexp.MustCompile(`^[A-Za-z0-9_\-+/]{16,}={0,2}$`)
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
	case shortHexRegex.MatchString(segment):
		// numericRegex was checked first, so an all-digit segment cannot reach
		// here. The remaining hex strings are short hashes.
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
//   - /tokens/ZXhhbXBsZS1iYXNlNjR1cmwtdG9rZW4      -> /tokens/{tokenToken}    (base64)
//   - /users/me                                    -> /users/me               (literal preserved)
//
// For slug-style identifiers that vary across observed paths, use
// NormalizePathsWithNames which performs observation-based detection.
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

// NormalizePathsWithNames runs NormalizePathWithNames on each input path and
// then performs observation-based detection: any path position whose value
// varies across paths sharing the same prefix and suffix shape is promoted
// to a slug-style parameter.
//
// Returns a map keyed by the original input path. When the same path appears
// multiple times the map collapses to a single normalized entry, which is
// the desired behavior for grouping observed endpoints.
func NormalizePathsWithNames(paths []string) map[string]string {
	if len(paths) == 0 {
		return map[string]string{}
	}

	infos := classifyPaths(paths)
	varyingPositions := findVaryingPositions(infos)
	promoteVaryingPositions(infos, varyingPositions)
	return renderNormalizedPaths(paths, infos)
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
// varying position bucket from kindLiteral to kindSlug.
func promoteVaryingPositions(infos []pathInfo, varying map[posKey]struct{}) {
	if len(varying) == 0 {
		return
	}
	for idx := range infos {
		info := infos[idx]
		for i, seg := range info.segments {
			if !isObservationCandidate(info, i, seg) {
				continue
			}
			if _, ok := varying[positionKey(info, i)]; ok {
				info.kinds[i] = kindSlug
			}
		}
		infos[idx] = info
	}
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
// non-empty literal segment. Observation-based detection requires this so
// that the very first resource segment of a path (which is the resource
// type, not a parameter) cannot be promoted to a parameter.
func hasLiteralContext(segments []string, kinds []paramKind) bool {
	for i, s := range segments {
		if s == "" {
			continue
		}
		if kinds[i] == kindLiteral {
			return true
		}
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

// sanitizeParamName removes characters that are not safe for OpenAPI parameter names.
// Allows alphanumeric characters, underscores, hyphens, and dots.
func sanitizeParamName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if result == "" {
		return "id"
	}
	return result
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
