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
	return &SchemaProbe{config: cfg}
}

// Name returns the probe name.
func (p *SchemaProbe) Name() string {
	return "schema"
}

// Probe enriches endpoints with inferred JSON schema from GET responses.
// Only endpoints with JSON content types are probed. Individual request
// failures are handled gracefully.
func (p *SchemaProbe) Probe(ctx context.Context, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	client := p.config.Client
	if client == nil {
		client = &http.Client{Timeout: p.config.Timeout}
	}

	result := make([]classify.ClassifiedRequest, len(endpoints))
	copy(result, endpoints)

	for i := range result {
		if !isJSONContentType(result[i].Response.ContentType) {
			continue
		}

		schema := p.probeURL(ctx, client, result[i].URL)
		if schema != nil {
			result[i].ResponseSchema = schema
		}
	}

	return result, nil
}

// probeURL sends a GET request and infers schema from the JSON response.
func (p *SchemaProbe) probeURL(ctx context.Context, client *http.Client, url string) map[string]interface{} {
	reqCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
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

	if !isJSONContentType(resp.Header.Get("Content-Type")) {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSchemaBodySize))
	if err != nil {
		return nil
	}

	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}

	return inferSchema(parsed)
}

// inferSchema infers a JSON-schema-like structure from a parsed JSON value.
func inferSchema(v interface{}) map[string]interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		props := make(map[string]interface{})
		for k, child := range val {
			props[k] = inferSchema(child)
		}
		return map[string]interface{}{
			"type":       "object",
			"properties": props,
		}

	case []interface{}:
		schema := map[string]interface{}{
			"type": "array",
		}
		if len(val) > 0 {
			schema["items"] = inferSchema(val[0])
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

// isJSONContentType checks if the content type indicates JSON.
func isJSONContentType(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "json")
}
