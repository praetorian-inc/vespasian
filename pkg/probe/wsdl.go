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

package probe

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// maxWSDLBodySize limits the response body read for WSDL documents.
const maxWSDLBodySize = 2 << 20 // 2 MB

// WSDLProbe fetches WSDL documents from discovered SOAP endpoints.
type WSDLProbe struct {
	config Config
}

// NewWSDLProbe creates a WSDLProbe with the given configuration.
func NewWSDLProbe(cfg Config) *WSDLProbe {
	return &WSDLProbe{config: cfg.withDefaults()}
}

// Name returns the probe name.
func (p *WSDLProbe) Name() string {
	return "wsdl"
}

// Probe fetches WSDL documents for SOAP endpoints by appending ?wsdl to the URL.
// Only endpoints with api_type=="wsdl" are probed. Endpoints are deduplicated
// by base URL to avoid redundant requests.
func (p *WSDLProbe) Probe(ctx context.Context, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	// Deduplicate: probe each unique base URL once
	wsdlDocs := make(map[string][]byte)
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		if ep.APIType != "wsdl" {
			continue
		}

		baseURL := stripWSDLSuffix(ep.URL)
		if seen[baseURL] {
			continue
		}
		if len(seen) >= p.config.MaxEndpoints {
			break
		}
		seen[baseURL] = true

		doc := p.fetchWSDL(ctx, baseURL)
		if doc != nil {
			wsdlDocs[baseURL] = doc
		}
	}

	// Copy endpoints to avoid mutating the caller's slice
	result := make([]classify.ClassifiedRequest, len(endpoints))
	copy(result, endpoints)

	for i := range result {
		if result[i].APIType != "wsdl" {
			continue
		}
		baseURL := stripWSDLSuffix(result[i].URL)
		if doc, ok := wsdlDocs[baseURL]; ok {
			result[i].WSDLDocument = doc
		}
	}

	return result, nil
}

// fetchWSDL appends ?wsdl to the URL and fetches the WSDL document.
func (p *WSDLProbe) fetchWSDL(ctx context.Context, baseURL string) []byte {
	wsdlURL := baseURL + "?wsdl"

	if err := p.config.URLValidator(wsdlURL); err != nil {
		slog.DebugContext(ctx, "wsdl probe: URL validation failed", "url", wsdlURL, "error", err)
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, wsdlURL, nil)
	if err != nil {
		return nil
	}

	for k, v := range p.config.AuthHeaders {
		req.Header.Set(k, v)
	}

	resp, err := p.config.Client.Do(req)
	if err != nil {
		slog.DebugContext(ctx, "wsdl probe: request failed", "url", wsdlURL, "error", err)
		return nil
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck // best-effort drain
		resp.Body.Close()                                    //nolint:errcheck // best-effort close
	}()

	if resp.StatusCode >= 400 {
		slog.DebugContext(ctx, "wsdl probe: non-success status", "url", wsdlURL, "status", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWSDLBodySize))
	if err != nil {
		return nil
	}

	// Validate response looks like WSDL XML
	if !isWSDLResponse(body) {
		slog.DebugContext(ctx, "wsdl probe: response is not WSDL", "url", wsdlURL)
		return nil
	}

	return body
}

// isWSDLResponse checks if the body looks like a WSDL document.
func isWSDLResponse(body []byte) bool {
	return bytes.Contains(body, []byte("definitions")) &&
		(bytes.Contains(body, []byte("schemas.xmlsoap.org/wsdl")) ||
			bytes.Contains(body, []byte("portType")) ||
			bytes.Contains(body, []byte("message")))
}

// stripWSDLSuffix removes ?wsdl query parameter or /wsdl path suffix from a URL.
func stripWSDLSuffix(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Remove ?wsdl query parameter
	q := parsed.Query()
	q.Del("wsdl")
	parsed.RawQuery = q.Encode()

	// Remove /wsdl path suffix
	parsed.Path = strings.TrimSuffix(parsed.Path, "/wsdl")

	return parsed.String()
}
