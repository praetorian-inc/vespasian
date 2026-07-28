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

package jsstatic

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// Next.js App Router route recovery (LAB-4678 audit item 7).
//
// The original Phase 2 investigation concluded that static extraction cannot
// recover endpoints from Next.js bundles, on the evidence that a marker scan of
// 44 RSC bundles found no "/api/" literal in any BODY. That finding is correct
// and still holds for RSC server actions, which build their paths at runtime.
//
// It is not the whole picture. The App Router names each page and route-handler
// chunk after the route's directory path, so the route is recoverable from the
// chunk URL without any literal in the body:
//
//	/_next/static/chunks/app/vaults/%5BvaultId%5D/page-8ca1aac6111f15fc.js
//	  -> /vaults/{vaultId}
//
// That exact URL appears in the LAB-4677 run-013 capture. This file recovers
// those routes. RSC server-action endpoints remain unrecoverable statically.

// nextChunkRe matches an App Router chunk URL path and captures the route
// directory portion and the chunk kind. Anchored on the framework's fixed
// "/_next/static/chunks/app/" prefix so no other asset path can match.
//
// The route directory may be empty (the root route), hence "(.*?)" plus an
// optional separator rather than a required one.
var nextChunkRe = regexp.MustCompile(
	`/_next/static/chunks/app/(.*?)/?(page|route)-[0-9A-Za-z_-]+\.js$`)

// nextSegmentRe matches a bracketed App Router dynamic segment: [id],
// [...slug] (catch-all), or [[...slug]] (optional catch-all).
var nextSegmentRe = regexp.MustCompile(`^\[{1,2}(?:\.\.\.)?([^\]]+)\]{1,2}$`)

// interceptRe matches App Router intercepting-route prefixes: (.), (..), (...)
// and (..)(..) forms that prefix a segment name.
var interceptRe = regexp.MustCompile(`^(?:\(\.{1,3}\))+`)

// nextRouteKind distinguishes the two recoverable chunk kinds.
type nextRouteKind int

const (
	nextRouteNone nextRouteKind = iota
	// nextRoutePage is app/<route>/page-<hash>.js — a navigational page route.
	nextRoutePage
	// nextRouteHandler is app/<route>/route-<hash>.js — a server HTTP endpoint.
	nextRouteHandler
)

// nextRouteFromChunkURL derives the application route served by a Next.js App
// Router chunk URL, or ("", nextRouteNone) when the URL is not such a chunk.
//
// The returned path is in the OpenAPI-friendly form used elsewhere in this
// package: dynamic segments render as {name}.
func nextRouteFromChunkURL(rawURL string) (string, nextRouteKind) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", nextRouteNone
	}
	// Match against the decoded path: Next.js percent-encodes the brackets of
	// dynamic segments in the emitted asset URL ("%5BvaultId%5D"), and url.Parse
	// exposes the decoded form on Path.
	m := nextChunkRe.FindStringSubmatch(parsed.Path)
	if m == nil {
		return "", nextRouteNone
	}

	kind := nextRoutePage
	if m[2] == "route" {
		kind = nextRouteHandler
	}

	route := normalizeNextRoute(m[1])
	return route, kind
}

// normalizeNextRoute converts an App Router directory path into a URL path.
//
// Segments that exist only in the filesystem and never appear in the URL are
// dropped: route groups "(marketing)", parallel-route slots "@modal", private
// folders "_components", and intercepting-route prefixes "(.)"/"(..)"/"(...)".
// Dynamic segments become OpenAPI-style parameters: "[id]" -> "{id}", and both
// catch-all forms "[...slug]" / "[[...slug]]" -> "{slug}", since a catch-all
// still names one path parameter as far as a spec is concerned.
func normalizeNextRoute(dir string) string {
	if dir == "" {
		return "/"
	}
	var out []string
	for _, seg := range strings.Split(dir, "/") {
		if seg == "" {
			continue
		}
		// Route groups and parallel-route slots never appear in the URL.
		if strings.HasPrefix(seg, "(") && strings.HasSuffix(seg, ")") {
			continue
		}
		if strings.HasPrefix(seg, "@") || strings.HasPrefix(seg, "_") {
			continue
		}
		// An intercepting prefix decorates a real segment; strip the prefix and
		// keep the segment it points at.
		seg = interceptRe.ReplaceAllString(seg, "")
		if seg == "" {
			continue
		}
		if m := nextSegmentRe.FindStringSubmatch(seg); m != nil {
			out = append(out, "{"+m[1]+"}")
			continue
		}
		out = append(out, seg)
	}
	if len(out) == 0 {
		return "/"
	}
	return "/" + strings.Join(out, "/")
}

// extractNextRoute returns the ExtractedEndpoint recovered from a chunk URL, or
// nil when the URL is not an App Router page/route chunk.
//
// Method is GET for both kinds. A route handler may export POST/PUT/DELETE as
// well, but the chunk URL does not say which verbs exist, and inventing them
// would fabricate endpoints that may not be served. GET is the one request that
// is safe to attribute, and the probe stage discovers the rest via OPTIONS.
func extractNextRoute(bundleURL, pageURL string) *ExtractedEndpoint {
	route, kind := nextRouteFromChunkURL(bundleURL)
	if kind == nextRouteNone {
		return nil
	}
	tag := crawl.SourceNextPageRoute
	if kind == nextRouteHandler {
		tag = crawl.SourceNextRouteHandler
	}
	return &ExtractedEndpoint{
		Method:       "GET",
		URL:          route,
		SourceTag:    tag,
		PageURL:      pageURL,
		OriginBundle: bundleURL,
	}
}
