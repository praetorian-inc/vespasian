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
	"context"
	"net/http"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// OptionsProbe sends OPTIONS requests to discover supported HTTP methods.
type OptionsProbe struct {
	config Config
}

// NewOptionsProbe creates an OptionsProbe with the given configuration.
func NewOptionsProbe(cfg Config) *OptionsProbe {
	return &OptionsProbe{config: cfg}
}

// Name returns the probe name.
func (p *OptionsProbe) Name() string {
	return "options"
}

// Probe enriches endpoints by sending OPTIONS requests to discover allowed methods.
// Endpoints are deduplicated by URL to avoid redundant requests. Individual request
// failures are handled gracefully — the endpoint is returned without enrichment.
func (p *OptionsProbe) Probe(ctx context.Context, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	client := p.config.Client
	if client == nil {
		client = &http.Client{Timeout: p.config.Timeout}
	}

	// Deduplicate: probe each unique URL once
	urlMethods := make(map[string][]string)
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		if seen[ep.URL] {
			continue
		}
		seen[ep.URL] = true

		methods := p.probeURL(ctx, client, ep.URL)
		if len(methods) > 0 {
			urlMethods[ep.URL] = methods
		}
	}

	// Apply results to all endpoints
	result := make([]classify.ClassifiedRequest, len(endpoints))
	copy(result, endpoints)

	for i := range result {
		if methods, ok := urlMethods[result[i].URL]; ok {
			result[i].AllowedMethods = methods
		}
	}

	return result, nil
}

// probeURL sends an OPTIONS request and returns the parsed Allow header methods.
func (p *OptionsProbe) probeURL(ctx context.Context, client *http.Client, url string) []string {
	reqCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodOptions, url, nil)
	if err != nil {
		return nil
	}

	for k, v := range p.config.AuthHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	return parseAllowHeader(resp.Header.Get("Allow"))
}

// parseAllowHeader parses the Allow header value into a slice of methods.
func parseAllowHeader(header string) []string {
	if header == "" {
		return nil
	}

	parts := strings.Split(header, ",")
	var methods []string

	for _, part := range parts {
		method := strings.TrimSpace(part)
		if method != "" {
			methods = append(methods, method)
		}
	}

	return methods
}
