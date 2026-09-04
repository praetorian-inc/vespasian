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

package crawl

// ObservedRequest represents a captured HTTP request and its response.
type ObservedRequest struct {
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	Headers     map[string]string   `json:"headers,omitempty"`
	QueryParams map[string][]string `json:"query_params,omitempty"`
	Body        []byte              `json:"body,omitempty"`
	Response    ObservedResponse    `json:"response"`
	// Source identifies the channel the request was observed on. Values produced
	// in tree: "browser" (network.go), "http" (http_crawler.go), "form"
	// (forms.go), "js-extract" (jsreplay.go); "import:burp", "import:har",
	// "import:mitmproxy" (pkg/importer); "static:html" (pkg/analyze); and from
	// pkg/analyze/jsstatic "static:js", "static:js-sourcemap", "static:js-concat"
	// (+-chain and service-prefix reconstruction, LAB-4992), "static:js-nextroute"
	// and "static:js-nextpage" (Next.js App Router chunk URLs). "katana" appears
	// in test fixtures only; nothing in tree sets it.
	Source    string `json:"source"`
	Tag       string `json:"tag,omitempty"`
	Attribute string `json:"attribute,omitempty"`
	PageURL   string `json:"page_url,omitempty"`
}

// Here rather than in a producer package: jsstatic writes these and
// pkg/generate/rest reads them for the x-vespasian-source extension, so this keeps
// them in sync without either importing the other.
const (
	// SourceStaticJS marks a request recovered as an AST literal from a JS bundle.
	SourceStaticJS = "static:js"
	// SourceStaticJSSourcemap marks one recovered from a .js.map sourcesContent entry.
	SourceStaticJSSourcemap = "static:js-sourcemap"
	// SourceStaticJSConcat marks a request reconstructed from JS string
	// concatenation (concat / +-chain / service-prefix, LAB-4992). These are
	// never probed on the offline path and involve speculative sentinel
	// substitution, so they are tagged distinctly from AST-recovered literals
	// (SourceStaticJS) to let downstream consumers weight them accordingly.
	SourceStaticJSConcat = "static:js-concat"
	// SourceNextRouteHandler marks a request recovered from a Next.js App Router
	// ROUTE HANDLER chunk URL (app/<route>/route-<hash>.js). The chunk proves the
	// framework serves that path, but not which verbs the module exports, so the
	// tag records provenance only and carries no API signal — see the note in
	// RESTClassifier.ClassifyDetail.
	SourceNextRouteHandler = "static:js-nextroute"
	// SourceNextPageRoute marks a request recovered from a Next.js App Router
	// PAGE chunk URL (app/<route>/page-<hash>.js). A page route is navigational,
	// not a REST endpoint, so it likewise carries no API signal and is surfaced
	// only as a near-miss under -v, matching crawled HTML page routes.
	SourceNextPageRoute = "static:js-nextpage"
)

// IsJSStaticSource reports whether source is one of the JS-bundle
// static-analysis values. "static:html" is excluded deliberately: different
// provenance.
func IsJSStaticSource(source string) bool {
	return source == SourceStaticJS ||
		source == SourceStaticJSSourcemap ||
		source == SourceStaticJSConcat ||
		source == SourceNextRouteHandler ||
		source == SourceNextPageRoute
}

// AnyStaticSource gates JS-specific metadata so none is emitted when no JS
// analysis ran.
func AnyStaticSource(reqs []ObservedRequest) bool {
	for _, r := range reqs {
		if IsJSStaticSource(r.Source) {
			return true
		}
	}
	return false
}

// ObservedResponse represents a captured HTTP response.
type ObservedResponse struct {
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Body        []byte            `json:"body,omitempty"`
}
