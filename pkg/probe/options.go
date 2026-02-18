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
	"io"
	"log/slog"
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
	return &OptionsProbe{config: cfg.withDefaults()}
}

// Name returns the probe name.
func (p *OptionsProbe) Name() string {
	return "options"
}

// Probe enriches endpoints by sending OPTIONS requests to discover allowed methods.
// Endpoints are deduplicated by URL to avoid redundant requests. Individual request
// failures are handled gracefully — the endpoint is returned without enrichment.
func (p *OptionsProbe) Probe(ctx context.Context, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	// Deduplicate: probe each unique URL once
	urlMethods := make(map[string][]string)
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		if seen[ep.URL] {
			continue
		}
		if len(seen) >= p.config.MaxEndpoints {
			break
		}
		seen[ep.URL] = true

		methods := p.probeURL(ctx, ep.URL)
		if len(methods) > 0 {
			urlMethods[ep.URL] = methods
		}
	}

	// Copy endpoints to avoid mutating the caller's slice. Note: the shallow copy
	// aliases mutable embedded fields (Headers, QueryParams maps) from ObservedRequest.
	// Probes write only to probe-enriched fields (AllowedMethods, ResponseSchema).
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
func (p *OptionsProbe) probeURL(ctx context.Context, url string) []string {
	if err := p.config.URLValidator(url); err != nil {
		slog.DebugContext(ctx, "options probe: URL validation failed", "url", url, "error", err)
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodOptions, url, nil)
	if err != nil {
		return nil
	}

	for k, v := range p.config.AuthHeaders {
		req.Header.Set(k, v)
	}

	resp, err := p.config.Client.Do(req)
	if err != nil {
		slog.DebugContext(ctx, "options probe: request failed", "url", url, "error", err)
		return nil
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck // best-effort drain
		resp.Body.Close()                                    //nolint:errcheck // best-effort close on read-only response
	}()

	if resp.StatusCode >= 400 {
		slog.DebugContext(ctx, "options probe: non-success status", "url", url, "status", resp.StatusCode)
		return nil
	}

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
			methods = append(methods, strings.ToUpper(method))
		}
	}

	return methods
}
