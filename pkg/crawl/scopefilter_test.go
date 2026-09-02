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

import "testing"

// TestScopeFilter_RetainsJSBundlesForStaticAnalysis pins that scope-filtering the
// passive capture does not also decide what pkg/analyze/jsstatic can see.
//
// jsstatic runs over the capture after the crawl and has no other input, so
// dropping an out-of-scope JS body silently disabled BOTH SPA bundle extraction and
// Next.js App Router route recovery for any target serving its bundles from a
// separate asset host — the normal Next.js deployment when assetPrefix or a CDN is
// configured. The operator saw a smaller spec, not an error.
//
// Removing the isRetainedForStaticAnalysis call in mergeEnrichedLinks fails this.
func TestScopeFilter_RetainsJSBundlesForStaticAnalysis(t *testing.T) {
	scopeFn, err := scopeChecker("https://app.example.com/", "same-origin", true)
	if err != nil {
		t.Fatal(err)
	}

	const cdnBundle = "https://cdn.example.com/_next/static/chunks/app/vaults/%5BvaultId%5D/page-abc123.js"
	captured := []ObservedRequest{
		{Method: "GET", URL: "https://app.example.com/",
			Response: ObservedResponse{StatusCode: 200, ContentType: "text/html"}},
		{Method: "GET", URL: cdnBundle,
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/javascript",
				Body: []byte(`fetch("/api/vaults")`)}},
		// A bundle whose content-type is missing, which is common on CDNs: the URL
		// extension has to carry it.
		{Method: "GET", URL: "https://static.example.com/assets/main.js",
			Response: ObservedResponse{StatusCode: 200, Body: []byte(`fetch("/api/orders")`)}},
		// Third-party XHR — the traffic the scope filter exists for. Must still go.
		{Method: "POST", URL: "https://analytics.vendor.com/collect",
			Response: ObservedResponse{StatusCode: 200, ContentType: "application/json"}},
	}

	out, _ := mergeEnrichedLinks(captured, nil, nil, nil, nil,
		"https://app.example.com/", "https://app.example.com/", scopeFn)

	kept := make(map[string]bool, len(out))
	for _, r := range out {
		kept[r.URL] = true
	}

	for _, want := range []string{cdnBundle, "https://static.example.com/assets/main.js"} {
		if !kept[want] {
			t.Errorf("cross-origin JS bundle %q was dropped from the capture; jsstatic runs "+
				"over the capture, so this silently disables bundle extraction and Next.js "+
				"route recovery for CDN-hosted apps", want)
		}
	}
	if kept["https://analytics.vendor.com/collect"] {
		t.Error("third-party XHR survived the scope filter; the JS exemption must not admit " +
			"ordinary out-of-scope API traffic")
	}
	if !kept["https://app.example.com/"] {
		t.Error("in-scope page was dropped")
	}
}

// TestIsRetainedForStaticAnalysis covers the predicate directly, including the
// media types and the URL fallback.
func TestIsRetainedForStaticAnalysis(t *testing.T) {
	cases := []struct {
		name string
		req  ObservedRequest
		want bool
	}{
		{"application/javascript", ObservedRequest{URL: "https://x/a",
			Response: ObservedResponse{ContentType: "application/javascript"}}, true},
		{"text/javascript with charset", ObservedRequest{URL: "https://x/a",
			Response: ObservedResponse{ContentType: "text/javascript; charset=utf-8"}}, true},
		{".js URL, no content-type", ObservedRequest{URL: "https://x/a/main.js"}, true},
		{".mjs URL", ObservedRequest{URL: "https://x/a/main.mjs"}, true},
		{".js with query string", ObservedRequest{URL: "https://x/a/main.js?v=2"}, true},
		{"json body", ObservedRequest{URL: "https://x/api/v1",
			Response: ObservedResponse{ContentType: "application/json"}}, false},
		{"html page", ObservedRequest{URL: "https://x/page",
			Response: ObservedResponse{ContentType: "text/html"}}, false},
		{"json endpoint whose path merely contains js", ObservedRequest{URL: "https://x/jsonapi/users",
			Response: ObservedResponse{ContentType: "application/json"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetainedForStaticAnalysis(tc.req); got != tc.want {
				t.Errorf("isRetainedForStaticAnalysis(%q, ct=%q) = %v, want %v",
					tc.req.URL, tc.req.Response.ContentType, got, tc.want)
			}
		})
	}
}
