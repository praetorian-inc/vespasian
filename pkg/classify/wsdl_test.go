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

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

func TestWSDLClassifier_Classify(t *testing.T) {
	c := &WSDLClassifier{}

	tests := []struct {
		name          string
		req           crawl.ObservedRequest
		wantIsAPI     bool
		wantMinConf   float64
		wantMaxConf   float64
		wantReasonSub string
	}{
		{
			name: "SOAPAction header",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Headers: map[string]string{
					"SOAPAction": `"urn:GetUser"`,
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.95,
			wantMaxConf:   1.0,
			wantReasonSub: "soapaction-header",
		},
		{
			name: "soap+xml content-type",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/soap+xml",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.85,
			wantMaxConf:   1.0,
			wantReasonSub: "soap-content-type",
		},
		{
			// text/xml is generic XML, not SOAP-specific, so on its own it scores
			// GenericXMLConfidence — below DefaultConfidenceThreshold and below
			// RESTClassifier's ContentTypeConfidence, so it is neither a WSDL match
			// nor a WSDL vote. It used to score 0.85, which outranked REST's 0.8 and
			// let one XML response type an entire capture as SOAP.
			name: "text/xml content-type alone is generic XML, not a SOAP signal",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/xml",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   GenericXMLConfidence,
			wantMaxConf:   GenericXMLConfidence,
			wantReasonSub: "generic-xml-content-type",
		},
		{
			// application/soap+xml IS SOAP-specific, so it keeps the full signal.
			name: "application/soap+xml content-type",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/soap+xml",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.85,
			wantMaxConf:   1.0,
			wantReasonSub: "soap-content-type",
		},
		{
			// A SOAP response with no SOAPAction and no request body still
			// identifies as SOAP, via the envelope in the RESPONSE. This is what
			// makes lowering bare text/xml safe.
			name: "soap envelope in response body, no SOAPAction",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/xml",
					Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
						`<soap:Body><GetUserResponse/></soap:Body></soap:Envelope>`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.90,
			wantMaxConf:   1.0,
			wantReasonSub: "soap-envelope",
		},
		{
			name: "SOAP envelope in body",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Body:   []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser/></soap:Body></soap:Envelope>`),
			},
			wantIsAPI:     true,
			wantMinConf:   0.90,
			wantMaxConf:   1.0,
			wantReasonSub: "soap-envelope",
		},
		{
			name: "SOAP-ENV envelope in body",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Body:   []byte(`<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body/></SOAP-ENV:Envelope>`),
			},
			wantIsAPI:     true,
			wantMinConf:   0.90,
			wantMaxConf:   1.0,
			wantReasonSub: "soap-envelope",
		},
		{
			name: "?wsdl URL",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/service?wsdl",
			},
			wantIsAPI:     true,
			wantMinConf:   0.90,
			wantMaxConf:   1.0,
			wantReasonSub: "wsdl-url",
		},
		{
			name: "/wsdl path",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/service/wsdl",
			},
			wantIsAPI:     true,
			wantMinConf:   0.90,
			wantMaxConf:   1.0,
			wantReasonSub: "wsdl-url",
		},
		{
			name: "RSS exclusion",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/feed",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/xml",
					Body:        []byte(`<rss version="2.0"><channel><title>My Feed</title></channel></rss>`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.3,
			wantMaxConf:   0.3,
			wantReasonSub: "generic-xml-content-type",
		},
		{
			name: "Atom feed exclusion",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/feed",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/xml",
					Body:        []byte(`<feed xmlns="http://www.w3.org/2005/Atom"><title>My Feed</title></feed>`),
				},
			},
			wantIsAPI:   true,
			wantMinConf: 0.3,
			wantMaxConf: 0.3,
		},
		{
			name: "HTML exclusion",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/page",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/html",
					Body:        []byte(`<html><body>Hello</body></html>`),
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "All signals combined",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Headers: map[string]string{
					"SOAPAction": `"urn:GetUser"`,
				},
				Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser/></soap:Body></soap:Envelope>`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/soap+xml",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.95,
			wantMaxConf:   1.0,
			wantReasonSub: "soapaction-header",
		},
		{
			name: "Static asset exclusion",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/app.js",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/xml",
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "JSON API not classified as WSDL",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/users",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"users":[]}`),
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAPI, confidence, reason := c.ClassifyDetail(tt.req)
			assert.Equal(t, tt.wantIsAPI, isAPI, "isAPI")
			assert.GreaterOrEqual(t, confidence, tt.wantMinConf, "confidence lower bound")
			assert.LessOrEqual(t, confidence, tt.wantMaxConf, "confidence upper bound")
			if tt.wantReasonSub != "" {
				assert.Contains(t, reason, tt.wantReasonSub, "reason")
			}
		})
	}
}

func TestWSDLClassifier_Name(t *testing.T) {
	c := &WSDLClassifier{}
	assert.Equal(t, "wsdl", c.Name())
}

func TestWSDLClassifier_ClassifyWrapper(t *testing.T) {
	c := &WSDLClassifier{}

	// Positive: request with SOAPAction header should be detected.
	pos := crawl.ObservedRequest{
		Method: "POST",
		URL:    "https://example.com/service",
		Headers: map[string]string{
			"SOAPAction": `"urn:GetUser"`,
		},
	}
	isAPI, confidence := c.Classify(pos)
	assert.True(t, isAPI, "expected SOAP request to be classified as API")
	assert.GreaterOrEqual(t, confidence, 0.95)

	// Negative: plain JSON endpoint should not be detected as WSDL.
	neg := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://example.com/api/users",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/json",
			Body:        []byte(`{"users":[]}`),
		},
	}
	isAPI, confidence = c.Classify(neg)
	assert.False(t, isAPI, "expected REST request to not be classified as WSDL")
	assert.Equal(t, 0.0, confidence)
}

func TestWSDLClassifier_ImplementsDetailedClassifier(t *testing.T) {
	var c APIClassifier = &WSDLClassifier{}
	assert.Implements(t, (*DetailedClassifier)(nil), c)
}

func TestWSDL_GenericXMLIsNotASoapVote(t *testing.T) {
	req := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://example.com/sitemap",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "text/xml",
			Body:        []byte("<urlset><url><loc>https://example.com/</loc></url></urlset>"),
		},
	}

	_, wsdlConf := (&WSDLClassifier{}).Classify(req)
	_, restConf := (&RESTClassifier{}).Classify(req)

	if wsdlConf >= restConf {
		t.Errorf("bare text/xml scores WSDL %.2f >= REST %.2f: it becomes a WSDL vote in "+
			"DetectAPIType, so one XML response can type an entire capture as SOAP",
			wsdlConf, restConf)
	}
	if wsdlConf >= DefaultConfidenceThreshold {
		t.Errorf("bare text/xml scores WSDL %.2f, at or above the %.2f threshold: generic XML "+
			"is not SOAP evidence and must not be a WSDL match at all",
			wsdlConf, DefaultConfidenceThreshold)
	}
}

func TestWSDL_RealSoapStillClassifies(t *testing.T) {
	cases := []struct {
		name string
		req  crawl.ObservedRequest
	}{
		{"SOAPAction header", crawl.ObservedRequest{
			Method: "POST", URL: "https://ex.com/svc",
			Headers:  map[string]string{"SOAPAction": `"urn:GetUser"`},
			Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "text/xml"},
		}},
		{"envelope in request body", crawl.ObservedRequest{
			Method: "POST", URL: "https://ex.com/svc",
			Body:     []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"/>`),
			Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "text/xml"},
		}},
		{"envelope in response body only", crawl.ObservedRequest{
			Method: "POST", URL: "https://ex.com/svc",
			Response: crawl.ObservedResponse{
				StatusCode: 200, ContentType: "text/xml",
				Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"/>`),
			},
		}},
		{"application/soap+xml", crawl.ObservedRequest{
			Method: "POST", URL: "https://ex.com/svc",
			Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/soap+xml"},
		}},
		{"?wsdl URL", crawl.ObservedRequest{
			Method: "GET", URL: "https://ex.com/svc?wsdl",
			Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "text/xml"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isAPI, conf := (&WSDLClassifier{}).Classify(tc.req)
			if !isAPI || conf < DefaultConfidenceThreshold {
				t.Errorf("genuine SOAP no longer classifies: isAPI=%v conf=%.2f", isAPI, conf)
			}
			_, restConf := (&RESTClassifier{}).Classify(tc.req)
			if conf < restConf {
				t.Errorf("SOAP scores %.2f below REST's %.2f, so it would lose the vote", conf, restConf)
			}
		})
	}
}
