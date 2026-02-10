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

package parser

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalOpenAPI returns a minimal valid OpenAPI 3.0 spec
func minimalOpenAPI() string {
	return `openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      operationId: getUsers
      summary: Get all users
      responses:
        '200':
          description: Success
`
}

// Test 1: Parse minimal valid spec
func TestParse_MinimalSpec(t *testing.T) {
	spec := minimalOpenAPI()
	reader := strings.NewReader(spec)

	endpoints, err := Parse(reader)

	require.NoError(t, err)
	assert.Len(t, endpoints, 1)
	assert.Equal(t, "GET", endpoints[0].Method)
	assert.Equal(t, "/users", endpoints[0].Path)
	assert.Equal(t, "getUsers", endpoints[0].OperationID)
}

// Test 2: Parse spec with all parameter locations
func TestParse_AllParameterLocations(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
        - name: filter
          in: query
          schema:
            type: string
        - name: X-API-Key
          in: header
          schema:
            type: string
        - name: session
          in: cookie
          schema:
            type: string
      responses:
        '200':
          description: Success
`
	reader := strings.NewReader(spec)

	endpoints, err := Parse(reader)

	require.NoError(t, err)
	require.Len(t, endpoints, 1)

	params := endpoints[0].Parameters
	assert.Len(t, params, 4)

	// Check all parameter locations are present
	locations := make(map[ParameterLocation]bool)
	for _, p := range params {
		locations[p.Location] = true
	}
	assert.True(t, locations[LocationPath])
	assert.True(t, locations[LocationQuery])
	assert.True(t, locations[LocationHeader])
	assert.True(t, locations[LocationCookie])
}

// Test 3: Parse spec with request body
func TestParse_RequestBody(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                email:
                  type: string
      responses:
        '201':
          description: Created
`
	reader := strings.NewReader(spec)

	endpoints, err := Parse(reader)

	require.NoError(t, err)
	require.Len(t, endpoints, 1)

	body := endpoints[0].RequestBody
	require.NotNil(t, body)
	assert.True(t, body.Required)
	assert.Equal(t, "application/json", body.ContentType)
	assert.NotNil(t, body.Schema)
	assert.Equal(t, "object", body.Schema.Type)
}

// Test 4: Parse spec with response schemas
func TestParse_ResponseSchemas(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      responses:
        '200':
          description: Success
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
        '404':
          description: Not found
        '500':
          description: Server error
`
	reader := strings.NewReader(spec)

	endpoints, err := Parse(reader)

	require.NoError(t, err)
	require.Len(t, endpoints, 1)

	responses := endpoints[0].Responses
	assert.Len(t, responses, 3)
	assert.Contains(t, responses, 200)
	assert.Contains(t, responses, 404)
	assert.Contains(t, responses, 500)

	// Check 200 response has schema
	assert.Equal(t, "Success", responses[200].Description)
	assert.Equal(t, "application/json", responses[200].ContentType)
	assert.NotNil(t, responses[200].Schema)
	assert.Equal(t, "array", responses[200].Schema.Type)
}

// Test 5: Parse spec with security requirements
func TestParse_SecurityRequirements(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      security:
        - bearerAuth: []
      responses:
        '200':
          description: Success
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
`
	reader := strings.NewReader(spec)

	endpoints, err := Parse(reader)

	require.NoError(t, err)
	require.Len(t, endpoints, 1)

	security := endpoints[0].Security
	require.Len(t, security, 1)
	assert.Equal(t, "bearerAuth", security[0].Scheme)
}

// Test 6: Parse YAML format
func TestParse_YAMLFormat(t *testing.T) {
	spec := minimalOpenAPI() // Already YAML
	reader := strings.NewReader(spec)

	endpoints, err := Parse(reader)

	require.NoError(t, err)
	assert.Len(t, endpoints, 1)
}

// Test 7: Parse spec with multiple endpoints
func TestParse_MultipleEndpoints(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      operationId: getUsers
      responses:
        '200':
          description: Success
    post:
      operationId: createUser
      responses:
        '201':
          description: Created
  /products:
    get:
      operationId: getProducts
      responses:
        '200':
          description: Success
`
	reader := strings.NewReader(spec)

	endpoints, err := Parse(reader)

	require.NoError(t, err)
	assert.Len(t, endpoints, 3)

	methods := make(map[string]bool)
	for _, ep := range endpoints {
		methods[ep.Method] = true
	}
	assert.True(t, methods["GET"])
	assert.True(t, methods["POST"])
}

// Test 8: Error on invalid spec
func TestParse_InvalidSpec(t *testing.T) {
	spec := `this is not valid YAML or JSON {{{`
	reader := strings.NewReader(spec)

	_, err := Parse(reader)

	assert.Error(t, err)
}

// Test 9: Error on empty input
func TestParse_EmptyInput(t *testing.T) {
	reader := strings.NewReader("")

	_, err := Parse(reader)

	assert.Error(t, err)
}

// Test 10: Parse spec with nested object schemas
func TestParse_NestedObjectSchemas(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                address:
                  type: object
                  properties:
                    street:
                      type: string
                    city:
                      type: string
      responses:
        '201':
          description: Created
`
	reader := strings.NewReader(spec)

	endpoints, err := Parse(reader)

	require.NoError(t, err)
	require.Len(t, endpoints, 1)

	body := endpoints[0].RequestBody
	require.NotNil(t, body)
	require.NotNil(t, body.Schema)

	// Check nested properties exist
	assert.NotNil(t, body.Schema.Properties)
	assert.Contains(t, body.Schema.Properties, "address")

	addressSchema := body.Schema.Properties["address"]
	assert.Equal(t, "object", addressSchema.Type)
	assert.NotNil(t, addressSchema.Properties)
	assert.Contains(t, addressSchema.Properties, "street")
	assert.Contains(t, addressSchema.Properties, "city")
}

// Test 11: ParseFile convenience function
func TestParseFile(t *testing.T) {
	// Create temp file with minimal spec
	tmpFile, err := os.CreateTemp("", "openapi-*.yaml")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	spec := minimalOpenAPI()
	_, err = tmpFile.WriteString(spec)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err, "failed to close temp file")

	endpoints, err := ParseFile(tmpFile.Name())

	require.NoError(t, err)
	assert.Len(t, endpoints, 1)
	assert.Equal(t, "GET", endpoints[0].Method)
	assert.Equal(t, "/users", endpoints[0].Path)
}
