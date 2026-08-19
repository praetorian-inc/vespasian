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
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// TestScopeExemptionCannotBecomeAnEndpoint pins the invariant that makes pkg/crawl's
// passive-capture scope exemption safe.
//
// crawl.isRetainedForStaticAnalysis deliberately keeps an out-of-scope response in the
// capture when it looks like JavaScript, so pkg/analyze/jsstatic can read a bundle
// served from a CDN or asset host. The argument for that hole is entirely downstream:
// a JavaScript response can never classify as an endpoint, so it can never reach the
// spec or the servers list. Nothing asserted it, and it was false in two ways.
//
// Every row below is a shape the retention predicate ADMITS, carrying the strongest
// API-shaped evidence a classifier can see (an API content-type plus a JSON object
// body, which the JSON-body rule alone scores above the default threshold). All three
// classifiers must reject every one of them, or an out-of-scope host becomes an
// operation in the emitted OpenAPI document and an entry in its servers list
// (LAB-4678 review, REQ-005 / TEST-015).
func TestScopeExemptionCannotBecomeAnEndpoint(t *testing.T) {
	// Each URL is out of scope for an app on app.example.com and is admitted into the
	// capture by crawl.isRetainedForStaticAnalysis — the first three by path suffix,
	// the last two by JavaScript content-type with no suffix to match on at all.
	cases := []struct {
		name        string
		url         string
		contentType string
	}{
		{".js served as JSON", "https://cdn.attacker.example/api/data.js", "application/json"},
		{".mjs served as JSON", "https://cdn.attacker.example/api/data.mjs", "application/json"},
		{".cjs served as JSON", "https://cdn.attacker.example/api/data.cjs", "application/json"},
		{"extensionless, application/javascript", "https://cdn.attacker.example/api/data", "application/javascript"},
		{"extensionless, text/javascript with charset", "https://cdn.attacker.example/v1/users", "text/javascript; charset=utf-8"},
	}

	classifiers := []APIClassifier{&RESTClassifier{}, &GraphQLClassifier{}, &WSDLClassifier{}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := crawl.ObservedRequest{
				Method: "GET",
				URL:    tc.url,
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: tc.contentType,
					Body:        []byte(`{"id":1,"name":"a"}`),
				},
			}

			got := RunClassifiers(classifiers, []crawl.ObservedRequest{req}, DefaultConfidenceThreshold)
			if len(got) != 0 {
				t.Errorf("RunClassifiers classified %d endpoint(s) for %q (ct=%q): %+v\n"+
					"this URL is in the capture only because crawl.isRetainedForStaticAnalysis "+
					"exempts JavaScript from the passive-capture scope filter; classifying it "+
					"puts an out-of-scope host in the spec and its servers list",
					len(got), tc.url, tc.contentType, got)
			}
		})
	}
}
