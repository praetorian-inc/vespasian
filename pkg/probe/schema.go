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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// maxSchemaBodySize limits the response body read for schema inference.
const maxSchemaBodySize = 1 << 20 // 1 MB

// SchemaProbe sends GET requests and infers JSON schema from responses.
type SchemaProbe struct {
	config Config
}

// NewSchemaProbe creates a SchemaProbe with the given configuration.
func NewSchemaProbe(cfg Config) *SchemaProbe {
	return &SchemaProbe{config: cfg.withDefaults()}
}

// Name returns the probe name.
func (p *SchemaProbe) Name() string {
	return "schema"
}

// Probe enriches endpoints with inferred JSON schema from GET responses.
// Only endpoints with JSON content types are probed. Endpoints are deduplicated
// by URL to avoid redundant requests. Individual request failures are handled
// gracefully.
func (p *SchemaProbe) Probe(ctx context.Context, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	// Deduplicate: probe each unique URL once
	urlSchemas := make(map[string]map[string]interface{})
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		if !isJSONContentType(ep.Response.ContentType) {
			continue
		}
		if seen[ep.URL] {
			continue
		}
		if len(seen) >= p.config.MaxEndpoints {
			break
		}
		seen[ep.URL] = true

		schema := p.probeURL(ctx, ep.URL)
		if schema != nil {
			urlSchemas[ep.URL] = schema
		}
	}

	// Copy endpoints to avoid mutating the caller's slice. Note: the shallow copy
	// aliases mutable embedded fields (Headers, QueryParams maps) from ObservedRequest.
	// Probes write only to probe-enriched fields (AllowedMethods, ResponseSchema).
	result := make([]classify.ClassifiedRequest, len(endpoints))
	copy(result, endpoints)

	for i := range result {
		if schema, ok := urlSchemas[result[i].URL]; ok {
			result[i].ResponseSchema = schema
		}
	}

	return result, nil
}

// probeURL sends a GET request and infers schema from the JSON response.
func (p *SchemaProbe) probeURL(ctx context.Context, url string) map[string]interface{} {
	if err := p.config.URLValidator(url); err != nil {
		slog.DebugContext(ctx, "schema probe: URL validation failed", "url", url, "error", err)
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	for k, v := range p.config.AuthHeaders {
		req.Header.Set(k, v)
	}

	resp, err := p.config.Client.Do(req) //nolint:gosec // G704: intentional outbound probe with SSRF protection
	if err != nil {
		slog.DebugContext(ctx, "schema probe: request failed", "url", url, "error", err)
		return nil
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck,gosec // best-effort drain
		resp.Body.Close()                                    //nolint:errcheck,gosec // best-effort close on read-only response
	}()

	if resp.StatusCode >= 400 {
		slog.DebugContext(ctx, "schema probe: non-success status", "url", url, "status", resp.StatusCode)
		return nil
	}

	if !isJSONContentType(resp.Header.Get("Content-Type")) {
		slog.DebugContext(ctx, "schema probe: non-JSON content type", "url", url, "content_type", resp.Header.Get("Content-Type"))
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSchemaBodySize))
	if err != nil {
		return nil
	}

	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		slog.DebugContext(ctx, "schema probe: JSON parse failed", "url", url, "error", err)
		return nil
	}

	return inferSchema(parsed)
}

// maxSchemaDepth limits recursion depth for schema inference.
const maxSchemaDepth = 64

// maxSchemaProperties limits the number of object properties inferred per level.
const maxSchemaProperties = 200

// inferSchema infers a JSON-schema-like structure from a parsed JSON value.
func inferSchema(v interface{}) map[string]interface{} {
	return inferSchemaDepth(v, 0)
}

// inferSchemaDepth recursively infers schema with a depth guard.
func inferSchemaDepth(v interface{}, depth int) map[string]interface{} {
	if depth > maxSchemaDepth {
		return map[string]interface{}{"type": "unknown"}
	}

	switch val := v.(type) {
	case map[string]interface{}:
		props := make(map[string]interface{})
		for k, child := range val {
			if len(props) >= maxSchemaProperties {
				break
			}
			props[k] = inferSchemaDepth(child, depth+1)
		}
		return map[string]interface{}{
			"type":       "object",
			"properties": props,
		}

	case []interface{}:
		schema := map[string]interface{}{
			"type": "array",
		}
		// Only the first element is sampled for item schema inference.
		// Heterogeneous arrays (mixed types) will reflect only the first element's type.
		if len(val) > 0 {
			schema["items"] = inferSchemaDepth(val[0], depth+1)
		}
		return schema

	case string:
		return map[string]interface{}{"type": "string"}

	case float64:
		return map[string]interface{}{"type": "number"}

	case bool:
		return map[string]interface{}{"type": "boolean"}

	case nil:
		return map[string]interface{}{"type": "null"}

	default:
		return map[string]interface{}{"type": "unknown"}
	}
}

// isJSONContentType checks if the content type indicates a JSON response.
// Matches standard patterns: "application/json", "text/json", and structured
// syntax suffixes like "application/vnd.api+json" and "application/problem+json".
func isJSONContentType(ct string) bool {
	ct = strings.ToLower(ct)
	// Strip charset parameters (e.g., "application/json; charset=utf-8").
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return strings.HasSuffix(ct, "/json") || strings.HasSuffix(ct, "+json")
}
