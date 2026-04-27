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
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// getHeader retrieves a header value case-insensitively. The exact-match
// shortcut at the top is a performance optimization for the common path
// (browser-lowercased "content-type"); the loop handles other casings such
// as Burp/HAR's title-case "Content-Type". Both branches return semantically
// identical results — the shortcut is not a behavioral distinction.
func getHeader(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok {
		return v
	}
	lower := strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) == lower {
			return v
		}
	}
	return ""
}

// ParseURLEncodedForm parses an application/x-www-form-urlencoded body into an
// OpenAPI SchemaRef (object with one property per field).
func ParseURLEncodedForm(body []byte) *openapi3.SchemaRef {
	if len(body) == 0 {
		return nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil || len(values) == 0 {
		return nil
	}
	schema := openapi3.NewObjectSchema()
	for key, vals := range values {
		t := inferQueryParamType(vals[0])
		schema.Properties[key] = openapi3.NewSchemaRef("", &openapi3.Schema{
			Type: &openapi3.Types{t},
		})
	}
	return openapi3.NewSchemaRef("", schema)
}

// ParseMultipartForm parses a multipart/form-data body into an OpenAPI SchemaRef.
// File upload fields get type: string, format: binary.
// boundary must be extracted from the Content-Type header of the observation.
func ParseMultipartForm(body []byte, boundary string) *openapi3.SchemaRef {
	if boundary == "" {
		return nil
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	schema := openapi3.NewObjectSchema()
	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		name := part.FormName()
		if name == "" {
			continue
		}
		if part.FileName() != "" {
			fileSchema := openapi3.NewStringSchema()
			fileSchema.Format = "binary"
			schema.Properties[name] = openapi3.NewSchemaRef("", fileSchema)
		} else {
			// Type inference only needs a small prefix of the value (we only check
			// for integer/number/boolean format); reading the entire part into memory
			// is wasteful for large text fields.
			var buf strings.Builder
			_, _ = io.Copy(&buf, io.LimitReader(part, 4096)) //nolint:errcheck // read from in-memory multipart part; errors are not actionable
			t := inferQueryParamType(buf.String())
			schema.Properties[name] = openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{t},
			})
		}
	}
	if len(schema.Properties) == 0 {
		return nil
	}
	return openapi3.NewSchemaRef("", schema)
}

// extractBoundary returns the multipart boundary from a Content-Type header value.
func extractBoundary(contentType string) string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return params["boundary"]
}

// mergeURLEncodedBodies merges URL-encoded form bodies across multiple observations
// into a single OpenAPI SchemaRef by taking the union of all observed properties.
func mergeURLEncodedBodies(bodies [][]byte) *openapi3.SchemaRef {
	var merged *openapi3.SchemaRef
	for _, body := range bodies {
		schema := ParseURLEncodedForm(body)
		merged = mergeObjectSchemas(merged, schema)
	}
	return merged
}

// mergeMultipartBodies merges multipart form bodies across multiple observations.
// contentTypes must correspond 1:1 with bodies; each entry is the full Content-Type
// header value for that observation (used to extract the per-observation boundary).
func mergeMultipartBodies(bodies [][]byte, contentTypes []string) *openapi3.SchemaRef {
	var merged *openapi3.SchemaRef
	for i, body := range bodies {
		ct := ""
		if i < len(contentTypes) {
			ct = contentTypes[i]
		}
		boundary := extractBoundary(ct)
		schema := ParseMultipartForm(body, boundary)
		merged = mergeObjectSchemas(merged, schema)
	}
	return merged
}

// mergeObjectSchemas merges overlay's properties into base and returns base.
// If both schemas define the same property with conflicting types, the property
// is promoted to string (matching the strategy used for JSON schema merging).
func mergeObjectSchemas(base, overlay *openapi3.SchemaRef) *openapi3.SchemaRef {
	if base == nil {
		return overlay
	}
	if overlay == nil {
		return base
	}
	if base.Value == nil || base.Value.Properties == nil ||
		overlay.Value == nil || overlay.Value.Properties == nil {
		return base
	}
	for k, v := range overlay.Value.Properties {
		if existing, ok := base.Value.Properties[k]; ok {
			if schemaTypesConflict(existing, v) {
				base.Value.Properties[k] = openapi3.NewSchemaRef("", openapi3.NewStringSchema())
			}
		} else {
			base.Value.Properties[k] = v
		}
	}
	return base
}

// schemaTypesConflict returns true if two SchemaRefs carry different non-empty type names.
func schemaTypesConflict(a, b *openapi3.SchemaRef) bool {
	if a == nil || b == nil || a.Value == nil || b.Value == nil {
		return false
	}
	if a.Value.Type == nil || b.Value.Type == nil {
		return false
	}
	aTypes := a.Value.Type.Slice()
	bTypes := b.Value.Type.Slice()
	if len(aTypes) == 0 || len(bTypes) == 0 {
		return false
	}
	return aTypes[0] != bTypes[0]
}
