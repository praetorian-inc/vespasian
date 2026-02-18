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

package rest

import (
	"encoding/json"
	"math"

	"github.com/getkin/kin-openapi/openapi3"
)

const (
	// maxBodySize is the maximum response body size for schema inference (10MB).
	maxBodySize = 10 * 1024 * 1024
	// maxSchemaDepth is the maximum nesting depth for recursive schema inference.
	maxSchemaDepth = 20
)

// InferSchema infers OpenAPI schema from JSON body.
func InferSchema(body []byte) *openapi3.SchemaRef {
	if len(body) == 0 {
		return nil
	}

	// Guard against excessively large bodies that could cause high memory usage.
	if len(body) > maxBodySize {
		return nil
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	return inferSchemaFromValue(data, 0)
}

func inferSchemaFromValue(value interface{}, depth int) *openapi3.SchemaRef {
	// Guard against deeply nested structures that could cause stack overflow.
	if depth >= maxSchemaDepth {
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"object"},
			},
		}
	}

	if value == nil {
		// OpenAPI 3.0 doesn't support type "null"; use nullable instead.
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Nullable: true,
			},
		}
	}

	switch v := value.(type) {
	case string:
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"string"},
			},
		}
	case float64:
		// Check if it's an integer within int64 range.
		// Values outside int64 range (e.g., 9999999999999999999) are classified as "number".
		if v == math.Trunc(v) && !math.IsInf(v, 0) && v >= math.MinInt64 && v <= math.MaxInt64 {
			return &openapi3.SchemaRef{
				Value: &openapi3.Schema{
					Type: &openapi3.Types{"integer"},
				},
			}
		}
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"number"},
			},
		}
	case bool:
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"boolean"},
			},
		}
	case []interface{}:
		// Array type
		schema := &openapi3.Schema{
			Type: &openapi3.Types{"array"},
		}
		// Infer item schema from first element if array is not empty
		if len(v) > 0 {
			schema.Items = inferSchemaFromValue(v[0], depth+1)
		}
		return &openapi3.SchemaRef{Value: schema}

	case map[string]interface{}:
		// Object type
		schema := &openapi3.Schema{
			Type:       &openapi3.Types{"object"},
			Properties: make(openapi3.Schemas),
		}
		// Infer schema for each property
		for key, val := range v {
			schema.Properties[key] = inferSchemaFromValue(val, depth+1)
		}
		return &openapi3.SchemaRef{Value: schema}

	default:
		// Unknown type, return string as fallback
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"string"},
			},
		}
	}
}
