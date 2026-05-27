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

func TestGRPCClassifier_Classify(t *testing.T) {
	c := &GRPCClassifier{}

	tests := []struct {
		name          string
		req           crawl.ObservedRequest
		wantIsAPI     bool
		wantConf      float64
		wantReasonSub string
	}{
		{
			name: "request content-type application/grpc",
			req: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/users.v1.UserService/GetUser",
				Headers: map[string]string{"Content-Type": "application/grpc"},
			},
			wantIsAPI:     true,
			wantConf:      GRPCContentTypeConfidence,
			wantReasonSub: "grpc-content-type",
		},
		{
			name: "request content-type application/grpc+proto",
			req: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/svc/Method",
				Headers: map[string]string{"content-type": "application/grpc+proto"},
			},
			wantIsAPI:     true,
			wantConf:      GRPCContentTypeConfidence,
			wantReasonSub: "grpc-content-type",
		},
		{
			name: "response content-type application/grpc-web",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/svc/Method",
				Response: crawl.ObservedResponse{
					ContentType: "application/grpc-web+proto",
				},
			},
			wantIsAPI:     true,
			wantConf:      GRPCContentTypeConfidence,
			wantReasonSub: "grpc-response-content-type",
		},
		{
			name: "grpc-status response header",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/whatever/Anything",
				Response: crawl.ObservedResponse{
					Headers: map[string]string{"grpc-status": "0"},
				},
			},
			wantIsAPI:     true,
			wantConf:      GRPCTrailerConfidence,
			wantReasonSub: "grpc-trailer-header",
		},
		{
			name: "grpc-message response header (case-insensitive)",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/foo/bar/baz",
				Response: crawl.ObservedResponse{
					Headers: map[string]string{"GRPC-Message": "OK"},
				},
			},
			wantIsAPI:     true,
			wantConf:      GRPCTrailerConfidence,
			wantReasonSub: "grpc-trailer-header",
		},
		{
			name: "POST with gRPC path shape only",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/users.v1.UserService/GetUser",
			},
			wantIsAPI:     true,
			wantConf:      GRPCPathConfidence,
			wantReasonSub: "grpc-path-shape",
		},
		{
			name: "POST with simple service path",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/Greeter/SayHello",
			},
			wantIsAPI:     true,
			wantConf:      GRPCPathConfidence,
			wantReasonSub: "grpc-path-shape",
		},
		// Negative cases
		{
			name: "GET on gRPC-shaped path is not gRPC",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/users.v1.UserService/GetUser",
			},
			wantIsAPI: false,
			wantConf:  0,
		},
		{
			name: "POST with REST path",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/api/users/123",
			},
			wantIsAPI: false,
			wantConf:  0,
		},
		{
			name: "POST with json content-type and json path",
			req: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/api/foo",
				Headers: map[string]string{"Content-Type": "application/json"},
			},
			wantIsAPI: false,
			wantConf:  0,
		},
		{
			name: "method starts with lowercase letter (proto style requires uppercase)",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/Greeter/sayHello",
			},
			wantIsAPI: false,
			wantConf:  0,
		},
		{
			name: "path too short (no method segment)",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/Greeter",
			},
			wantIsAPI: false,
			wantConf:  0,
		},
		{
			name: "content-type and path stack into reason; max wins on confidence",
			req: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/Service/Method",
				Headers: map[string]string{"Content-Type": "application/grpc"},
			},
			wantIsAPI:     true,
			wantConf:      GRPCContentTypeConfidence,
			wantReasonSub: "grpc-content-type+grpc-path-shape",
		},
		{
			name: "content-type + trailer boosted to HTTP/2-style confidence",
			req: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/api/foo",
				Headers: map[string]string{"Content-Type": "application/grpc"},
				Response: crawl.ObservedResponse{
					Headers: map[string]string{"grpc-status": "0"},
				},
			},
			wantIsAPI:     true,
			wantConf:      GRPCContentTypeTrailerConfidence,
			wantReasonSub: "grpc-content-type+grpc-trailer-header",
		},
		{
			name: "response content-type + trailer also boosted",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/api/foo",
				Response: crawl.ObservedResponse{
					ContentType: "application/grpc-web+proto",
					Headers:     map[string]string{"grpc-status": "0"},
				},
			},
			wantIsAPI:     true,
			wantConf:      GRPCContentTypeTrailerConfidence,
			wantReasonSub: "grpc-response-content-type+grpc-trailer-header",
		},
		{
			name: "trailer + path: max wins (0.80), both reasons present",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/users.v1.UserService/GetUser",
				Response: crawl.ObservedResponse{
					Headers: map[string]string{"grpc-status": "0"},
				},
			},
			wantIsAPI:     true,
			wantConf:      GRPCTrailerConfidence,
			wantReasonSub: "grpc-trailer-header+grpc-path-shape",
		},
		{
			name: "all three signals → content-type+trailer boost wins, all three reasons in string",
			req: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/users.v1.UserService/GetUser",
				Headers: map[string]string{"Content-Type": "application/grpc"},
				Response: crawl.ObservedResponse{
					Headers: map[string]string{"grpc-status": "0"},
				},
			},
			wantIsAPI:     true,
			wantConf:      GRPCContentTypeTrailerConfidence,
			wantReasonSub: "grpc-content-type+grpc-trailer-header+grpc-path-shape",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAPI, confidence, reason := c.ClassifyDetail(tt.req)
			assert.Equal(t, tt.wantIsAPI, isAPI, "isAPI")
			assert.Equal(t, tt.wantConf, confidence, "confidence")
			if tt.wantReasonSub != "" {
				assert.Contains(t, reason, tt.wantReasonSub, "reason")
			}
		})
	}
}

func TestGRPCClassifier_Name(t *testing.T) {
	c := &GRPCClassifier{}
	assert.Equal(t, "grpc", c.Name())
}

func TestGRPCClassifier_ClassifyMatchesDetail(t *testing.T) {
	c := &GRPCClassifier{}
	req := crawl.ObservedRequest{
		Method:  "POST",
		URL:     "https://example.com/svc/Method",
		Headers: map[string]string{"Content-Type": "application/grpc"},
	}
	isAPI, conf := c.Classify(req)
	isAPI2, conf2, _ := c.ClassifyDetail(req)
	assert.Equal(t, isAPI2, isAPI)
	assert.Equal(t, conf2, conf)
}
