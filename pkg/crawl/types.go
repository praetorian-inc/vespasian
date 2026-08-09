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
	// Source identifies the channel the request was observed on. Known values:
	//
	//   - "katana", "browser"            (live crawl, see pkg/crawl)
	//   - "form"                         (form submission, see pkg/crawl)
	//   - "import:burp", "import:har",
	//     "import:mitmproxy"             (offline imports, see pkg/importer)
	//   - "static:html"                  (static analysis of HTML <form> elements, pkg/analyze)
	//   - "static:js"                    (static analysis of JS bundles, pkg/analyze/jsstatic)
	//   - "static:js-sourcemap"          (recovered via .js.map sourcesContent)
	//   - "static:js-concat"             (concat / +-chain / service-prefix reconstruction, LAB-4992)
	Source    string `json:"source"`
	Tag       string `json:"tag,omitempty"`
	Attribute string `json:"attribute,omitempty"`
	PageURL   string `json:"page_url,omitempty"`
}

// Canonical Source values for static-analysis-derived requests. These live in
// pkg/crawl because Source is a field of ObservedRequest (defined here) and the
// values form a shared vocabulary across packages: pkg/analyze/jsstatic writes
// them and pkg/generate/rest reads them to derive the x-vespasian-source
// OpenAPI extension. Defining them here keeps the producer and consumer in
// sync without either package having to import the other.
const (
	// SourceStaticJS marks a request synthesized from static analysis of a JS bundle.
	SourceStaticJS = "static:js"
	// SourceStaticJSSourcemap marks a request synthesized from a recovered .js.map source.
	SourceStaticJSSourcemap = "static:js-sourcemap"
	// SourceStaticJSConcat marks a request reconstructed from JS string
	// concatenation (concat / +-chain / service-prefix, LAB-4992). These are
	// never probed on the offline path and involve speculative sentinel
	// substitution, so they are tagged distinctly from AST-recovered literals
	// (SourceStaticJS) to let downstream consumers weight them accordingly.
	SourceStaticJSConcat = "static:js-concat"
)

// IsJSStaticSource returns true iff source is one of the JS-bundle
// static-analysis Source values (SourceStaticJS, SourceStaticJSSourcemap, or
// SourceStaticJSConcat). Other "static:*" sources (e.g. "static:html" from HTML
// form analysis) are intentionally excluded — they have separate provenance.
func IsJSStaticSource(source string) bool {
	return source == SourceStaticJS ||
		source == SourceStaticJSSourcemap ||
		source == SourceStaticJSConcat
}

// AnyStaticSource reports whether any ObservedRequest in reqs carries a
// JS-bundle static-analysis Source value. Useful as a gate to avoid emitting
// JS-specific metadata (e.g. x-vespasian-source) when no JS analysis ran.
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
