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

package pipeline_test

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	restgen "github.com/praetorian-inc/vespasian/pkg/generate/rest"
)

func xmlResponse(url string) crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method: "GET", URL: url,
		Response: crawl.ObservedResponse{
			StatusCode: 200, ContentType: "text/xml",
			Body: []byte("<urlset><url><loc>https://ex.com/</loc></url></urlset>"),
		},
	}
}

func jsonResponse(url string) crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method: "GET", URL: url,
		Response: crawl.ObservedResponse{
			StatusCode: 200, ContentType: "application/json", Body: []byte(`{"a":1}`),
		},
	}
}

// TestDetectAPIType_GenericXMLDoesNotTypeTheCapture is the end-to-end assertion for
// the defect: DetectAPIType returned "wsdl" for a capture whose only classified
// request was one text/xml response, switching the generator from OpenAPI to WSDL.
func TestDetectAPIType_GenericXMLDoesNotTypeTheCapture(t *testing.T) {
	t.Run("lone XML response stays REST", func(t *testing.T) {
		got := pipeline.DetectAPIType([]crawl.ObservedRequest{xmlResponse("https://ex.com/sitemap")}, 0.5)
		if got != pipeline.APITypeREST {
			t.Errorf("DetectAPIType(one text/xml response) = %q, want %q: one XML document "+
				"must not type an entire capture as SOAP", got, pipeline.APITypeREST)
		}
	})

	// The old rule flipped a 3-REST capture to WSDL at 5 stray XML responses.
	t.Run("XML responses never out-vote a REST surface", func(t *testing.T) {
		var reqs []crawl.ObservedRequest
		for range 3 {
			reqs = append(reqs, jsonResponse("https://ex.com/api/thing"))
		}
		for n := range 12 {
			withXML := append([]crawl.ObservedRequest{}, reqs...)
			for i := 0; i <= n; i++ {
				withXML = append(withXML, xmlResponse("https://ex.com/feedish"))
			}
			if got := pipeline.DetectAPIType(withXML, 0.5); got != pipeline.APITypeREST {
				t.Fatalf("3 REST + %d text/xml = %q, want %q", n+1, got, pipeline.APITypeREST)
			}
		}
	})

	// Genuine SOAP must still win, or the fix has traded one wrong answer for another.
	t.Run("real SOAP still detected", func(t *testing.T) {
		soap := crawl.ObservedRequest{
			Method: "POST", URL: "https://ex.com/svc",
			Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			Response: crawl.ObservedResponse{
				StatusCode: 200, ContentType: "text/xml",
				Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"/>`),
			},
		}
		reqs := []crawl.ObservedRequest{soap, soap, soap, jsonResponse("https://ex.com/api/x")}
		if got := pipeline.DetectAPIType(reqs, 0.5); got != pipeline.APITypeWSDL {
			t.Errorf("a SOAP-dominant capture typed %q, want %q", got, pipeline.APITypeWSDL)
		}
	})
}

// TestSchemaUnion_SurvivesTheDefaultPipeline drives the union through the path
// production actually takes — RunClassifiers, then Deduplicate, then Generate —
// rather than calling buildOperation directly. The PR's own array-union test drove
// buildOperation, which passed while Deduplicate collapsed the two observations
// before the generator ever saw them.
func TestSchemaUnion_SurvivesTheDefaultPipeline(t *testing.T) {
	mk := func(url, body string) crawl.ObservedRequest {
		return crawl.ObservedRequest{
			Method: "GET", URL: url,
			Response: crawl.ObservedResponse{
				StatusCode: 200, ContentType: "application/json", Body: []byte(body),
			},
		}
	}
	cases := []struct {
		name   string
		bodies []string
		fields []string
	}{
		{
			name:   "top-level array (the collection endpoint case)",
			bodies: []string{`[{"id":1,"name":"a"}]`, `[{"id":2,"email":"b@x"}]`},
			fields: []string{"id", "name", "email"},
		},
		{
			name:   "nested object",
			bodies: []string{`{"user":{"id":1,"name":"a"}}`, `{"user":{"id":2,"email":"b@x"}}`},
			fields: []string{"id", "name", "email"},
		},
		{
			name:   "top-level object",
			bodies: []string{`{"id":1,"name":"a"}`, `{"id":2,"email":"b@x"}`},
			fields: []string{"id", "name", "email"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reqs []crawl.ObservedRequest
			for _, b := range tc.bodies {
				reqs = append(reqs, mk("https://ex.com/users", b))
			}
			classified := classify.RunClassifiers(
				[]classify.APIClassifier{&classify.RESTClassifier{}}, reqs, 0.5)
			// Deduplicate is on by default for both `scan` and `generate`.
			deduped := classify.Deduplicate(classified)
			g := &restgen.OpenAPIGenerator{}
			raw, err := g.Generate(deduped)
			if err != nil {
				t.Fatal(err)
			}
			spec := string(raw)
			for _, f := range tc.fields {
				if !strings.Contains(spec, f+":") {
					t.Errorf("field %q missing from the generated schema; the union did not run "+
						"on the deduplicated input:\n%s", f, spec)
				}
			}
		})
	}
}
