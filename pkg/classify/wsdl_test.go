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
	"github.com/stretchr/testify/assert"
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
			name: "text/xml content-type",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/xml",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.85,
			wantMaxConf:   1.0,
			wantReasonSub: "soap-content-type",
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
			wantReasonSub: "soap-content-type",
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

func TestWSDLClassifier_ImplementsDetailedClassifier(t *testing.T) {
	var c APIClassifier = &WSDLClassifier{}
	assert.Implements(t, (*DetailedClassifier)(nil), c)
}
