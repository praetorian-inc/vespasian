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
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/mediatype"
)

// capitalizeFirst capitalizes the first letter of a string (UTF-8 safe).
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[size:]
}

// inferQueryParamItemsType infers the OpenAPI items type from a slice of
// observed query-parameter values. Returns:
//   - "integer" if every value parses as int
//   - "number"  if every value parses as float (and at least one is non-int)
//   - "boolean" if every value is "true" or "false"
//   - "string"  otherwise (mixed or string)
func inferQueryParamItemsType(values []string) string {
	if len(values) == 0 {
		return "string"
	}
	allInt, allFloat, allBool := true, true, true
	for _, v := range values {
		if _, err := strconv.Atoi(v); err != nil {
			allInt = false
		}
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			allFloat = false
		}
		if v != "true" && v != "false" {
			allBool = false
		}
	}
	switch {
	case allInt:
		return "integer"
	case allFloat:
		return "number"
	case allBool:
		return "boolean"
	default:
		return "string"
	}
}

// inferQueryParamType infers the OpenAPI type from a single query parameter
// value. Used by pkg/generate/rest/form.go for form-field type inference where
// only one value per field is observed at a time. The OpenAPI generation path
// for multi-value/scalar query parameters uses inferQueryParamItemsType so the
// scalar branch of buildOperation classifies a slice of observed values
// consistently with the array branch.
//
// Implemented as a thin wrapper around inferQueryParamItemsType so the
// integer/number/boolean/string precedence stays in one place.
func inferQueryParamType(value string) string {
	return inferQueryParamItemsType([]string{value})
}

// OpenAPIGenerator generates OpenAPI 3.0 specifications.
type OpenAPIGenerator struct {
	// Format specifies the output format: "json" or "yaml" (default: "yaml")
	Format string
}

// explodeTrue is a singleton pointer target for setting the Explode field on
// OpenAPI Parameter objects. Hoisted to package level because the OpenAPI
// schema model uses `*bool` for tri-state, requiring an addressable value.
var explodeTrue = true

// endpointKey groups endpoints by normalized path and HTTP method.
type endpointKey struct {
	path   string
	method string
}

// APIType returns the API type.
func (g *OpenAPIGenerator) APIType() string {
	return "rest"
}

// extractServers extracts unique server URLs from endpoints and returns the server list and title host.
func extractServers(endpoints []classify.ClassifiedRequest) (openapi3.Servers, string) {
	serverSet := make(map[string]bool)
	var servers openapi3.Servers
	titleHost := "API"

	for _, endpoint := range endpoints {
		parsedURL, err := url.Parse(endpoint.URL)
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
			continue
		}
		baseURL := parsedURL.Scheme + "://" + parsedURL.Host
		if !serverSet[baseURL] {
			serverSet[baseURL] = true
			servers = append(servers, &openapi3.Server{URL: baseURL})
		}
	}

	if len(servers) > 0 {
		// Use first server's host for title
		firstURL, _ := url.Parse(servers[0].URL) //nolint:errcheck // nil check below handles parse failure
		if firstURL != nil {
			titleHost = firstURL.Host + " API"
		}
	}

	return servers, titleHost
}

// groupEndpoints groups and sorts endpoints by normalized path and HTTP method.
//
// Path normalization runs in two passes so that slug-style identifiers can be
// detected from the population of observed paths. The first pass parses URLs
// and collects their paths; the second pass calls NormalizePathsWithNames
// once, which performs both regex-based and observation-based detection.
func groupEndpoints(endpoints []classify.ClassifiedRequest) map[endpointKey][]classify.ClassifiedRequest {
	type parsedEndpoint struct {
		path     string
		endpoint classify.ClassifiedRequest
	}
	parsed := make([]parsedEndpoint, 0, len(endpoints))
	rawPaths := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		parsedURL, err := url.Parse(endpoint.URL)
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
			// Skip malformed URLs or non-HTTP/HTTPS schemes
			continue
		}
		parsed = append(parsed, parsedEndpoint{path: parsedURL.Path, endpoint: endpoint})
		rawPaths = append(rawPaths, parsedURL.Path)
	}

	normalized := NormalizePathsWithNames(rawPaths)

	endpointGroups := make(map[endpointKey][]classify.ClassifiedRequest)
	for _, p := range parsed {
		key := endpointKey{normalized[p.path], strings.ToLower(p.endpoint.Method)}
		endpointGroups[key] = append(endpointGroups[key], p.endpoint)
	}
	return endpointGroups
}

// anyStaticSource returns true if any request in endpoints has a Source that
// starts with "static:". This is used to gate the x-vespasian-source extension:
// when no static sources are present in the entire input the extension is omitted
// so output remains byte-identical to pre-LAB-2108 behavior.
func anyStaticSource(endpoints []classify.ClassifiedRequest) bool {
	for _, ep := range endpoints {
		if strings.HasPrefix(ep.Source, "static:") {
			return true
		}
	}
	return false
}

// computeSourceTag derives the x-vespasian-source value for an operation group.
// Mapping (architecture.md §7):
//   - any request with Source not starting "static:" (including empty Source from
//     pre-LAB-2108 captures or untagged dynamic entries) → "dynamic"
//   - all requests Source == "static:js"             → "js-bundle"
//   - all requests Source == "static:js-sourcemap"   → "js-sourcemap"
//   - mixed static prefixes within a group           → "dynamic"
//
// Empty Source is treated as a dynamic signal so that a group containing both
// dynamic (untagged) and static entries resolves to "dynamic" rather than
// inheriting the static tag from the static-only subset.
func computeSourceTag(group []classify.ClassifiedRequest) string {
	var tag string
	for _, ep := range group {
		if !strings.HasPrefix(ep.Source, "static:") {
			// Any dynamic source (including the empty/untagged case) wins immediately.
			return "dynamic"
		}
		// Static source: map to friendly name.
		var friendly string
		switch ep.Source {
		case "static:js":
			friendly = "js-bundle"
		case "static:js-sourcemap":
			friendly = "js-sourcemap"
		default:
			friendly = strings.TrimPrefix(ep.Source, "static:")
		}
		if tag == "" {
			tag = friendly
			continue
		}
		if tag != friendly {
			return "dynamic"
		}
	}
	return tag
}

// mergeJSONBodies infers and merges JSON schemas from multiple body observations.
func mergeJSONBodies(bodies [][]byte) *openapi3.SchemaRef {
	var merged *openapi3.SchemaRef
	for _, body := range bodies {
		if len(body) == 0 {
			continue
		}
		schema := InferSchema(body)
		if schema == nil {
			continue
		}
		// Delegate to mergeObjectSchemas (defined in form.go) so JSON, urlencoded,
		// and multipart all share the same conflict-resolution semantics: union
		// of properties; conflicting types promote to string.
		merged = mergeObjectSchemas(merged, schema)
	}
	return merged
}

// buildOperation builds a single OpenAPI operation from a group of classified requests.
// emitSource controls whether the x-vespasian-source extension is set on the operation.
// It should be true only when at least one request in the entire Generate input carries
// a "static:*" Source value (so flag-off output stays byte-identical to pre-LAB-2108).
func buildOperation(key endpointKey, group []classify.ClassifiedRequest, emitSource bool) *openapi3.Operation { //nolint:gocyclo // OpenAPI operation builder
	operation := &openapi3.Operation{
		Summary:   capitalizeFirst(key.method) + " " + key.path,
		Responses: &openapi3.Responses{},
	}

	if len(group) == 0 {
		return operation
	}

	// --- Query parameters: collect union from all endpoints, track frequency, values, and multi-value ---
	type queryParamInfo struct {
		count          int      // # of endpoints observing this param (for `required`)
		values         []string // union of ALL values seen, order-preserved (for items inference + array detection)
		multiValueSeen bool     // true iff any single observation had >1 values
	}
	queryParams := make(map[string]*queryParamInfo)
	endpointsWithParams := 0
	for _, ep := range group {
		if len(ep.QueryParams) > 0 {
			endpointsWithParams++
		}
		for name, vals := range ep.QueryParams {
			info, ok := queryParams[name]
			if !ok {
				info = &queryParamInfo{}
				queryParams[name] = info
			}
			info.count++
			// Prefer the per-observation truth recorded by RunClassifiers
			// (MultiValueQueryKeys) — that survives Deduplicate's
			// union-merge, whereas len(vals) > 1 here can falsely fire
			// when dedup merged two scalar observations of the same key
			// with different values. Fall back to len-based detection
			// only when MultiValueQueryKeys is nil (direct test
			// construction that doesn't go through RunClassifiers).
			if ep.MultiValueQueryKeys != nil {
				if ep.MultiValueQueryKeys[name] {
					info.multiValueSeen = true
				}
			} else if len(vals) > 1 {
				info.multiValueSeen = true
			}
			info.values = classify.MergeUniqueOrdered(info.values, vals)
		}
	}
	if len(queryParams) > 0 {
		// Sort parameter names for deterministic output
		paramNames := make([]string, 0, len(queryParams))
		for name := range queryParams {
			paramNames = append(paramNames, name)
		}
		sort.Strings(paramNames)

		operation.Parameters = make(openapi3.Parameters, 0, len(queryParams))
		for _, name := range paramNames {
			info := queryParams[name]
			// Required if present in all endpoints that have query params
			required := endpointsWithParams > 0 && info.count == endpointsWithParams

			if len(info.values) == 0 {
				continue // No observed values; cannot document this parameter accurately.
			}

			var param *openapi3.Parameter
			if info.multiValueSeen {
				// Emit array parameter with items type, style=form, explode=true
				itemsType := inferQueryParamItemsType(info.values)
				schema := &openapi3.Schema{
					Type: &openapi3.Types{"array"},
					Items: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type: &openapi3.Types{itemsType},
						},
					},
				}
				param = &openapi3.Parameter{
					Name:     name,
					In:       "query",
					Required: required,
					Schema:   &openapi3.SchemaRef{Value: schema},
					Style:    "form",
					Explode:  &explodeTrue,
				}
			} else {
				// Emit scalar parameter; walk all observed values so type
				// inference is order-independent (e.g., "1" then "1.5" → number).
				paramType := inferQueryParamItemsType(info.values)
				param = &openapi3.Parameter{
					Name:     name,
					In:       "query",
					Required: required,
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type: &openapi3.Types{paramType},
						},
					},
				}
			}
			operation.Parameters = append(operation.Parameters, &openapi3.ParameterRef{Value: param})
		}
	}

	// Add path parameters (extract from normalized path dynamically)
	pathParamNames := extractPathParams(key.path)
	for _, paramName := range pathParamNames {
		param := &openapi3.Parameter{
			Name:     paramName,
			In:       "path",
			Required: true,
			Schema: &openapi3.SchemaRef{
				Value: &openapi3.Schema{
					Type: &openapi3.Types{"string"},
				},
			},
		}
		operation.Parameters = append(operation.Parameters, &openapi3.ParameterRef{Value: param})
	}

	// --- Request body: partition by content type and merge ---
	if key.method == "post" || key.method == "put" || key.method == "patch" {
		type bodyObs struct {
			body        []byte
			contentType string
		}
		ctGroups := map[string][]bodyObs{}

		for _, ep := range group {
			if len(ep.Body) == 0 {
				continue
			}
			ct := getHeader(ep.Headers, "content-type")
			baseType := "application/json"
			if ct != "" {
				if t := mediatype.Base(ct); t != "" {
					baseType = t
				}
			}
			ctGroups[baseType] = append(ctGroups[baseType], bodyObs{body: ep.Body, contentType: ct})
		}

		if len(ctGroups) > 0 {
			content := openapi3.Content{}
			ctKeys := make([]string, 0, len(ctGroups))
			for k := range ctGroups {
				ctKeys = append(ctKeys, k)
			}
			sort.Strings(ctKeys)
			for _, mediaType := range ctKeys {
				obs := ctGroups[mediaType]
				bodies := make([][]byte, len(obs))
				contentTypes := make([]string, len(obs))
				for i, o := range obs {
					bodies[i] = o.body
					contentTypes[i] = o.contentType
				}
				var schema *openapi3.SchemaRef
				switch mediaType {
				case "application/x-www-form-urlencoded":
					schema = mergeURLEncodedBodies(bodies)
				case "multipart/form-data":
					schema = mergeMultipartBodies(bodies, contentTypes)
				default:
					schema = mergeJSONBodies(bodies)
				}
				if schema != nil {
					content[mediaType] = &openapi3.MediaType{Schema: schema}
				}
			}
			if len(content) > 0 {
				operation.RequestBody = &openapi3.RequestBodyRef{
					Value: &openapi3.RequestBody{
						Content: content,
					},
				}
			}
		}
	}

	// --- Responses: collect all distinct status codes, merge schemas ---
	seenStatus := make(map[string]*openapi3.ResponseRef)
	for _, ep := range group {
		statusCode := "200"
		statusInt := 200
		if sc := ep.Response.StatusCode; sc > 0 {
			statusCode = strconv.Itoa(sc)
			statusInt = sc
		}

		if existing, ok := seenStatus[statusCode]; ok {
			// Merge response body schema if both are objects
			if len(ep.Response.Body) > 0 && existing.Value != nil && existing.Value.Content != nil {
				// Only infer JSON schema for JSON-compatible content types
				ct := strings.ToLower(ep.Response.ContentType)
				if ct == "" || strings.Contains(ct, "json") {
					newSchema := InferSchema(ep.Response.Body)
					if newSchema != nil && newSchema.Value != nil && newSchema.Value.Properties != nil {
						if mt := existing.Value.Content["application/json"]; mt != nil && mt.Schema != nil &&
							mt.Schema.Value != nil && mt.Schema.Value.Properties != nil {
							for propName, propSchema := range newSchema.Value.Properties {
								if _, exists := mt.Schema.Value.Properties[propName]; !exists {
									mt.Schema.Value.Properties[propName] = propSchema
								}
							}
						}
					}
				}
			}
			continue
		}

		description := http.StatusText(statusInt)
		if description == "" {
			description = statusCode
		}
		response := &openapi3.Response{
			Description: &description,
		}

		if len(ep.Response.Body) > 0 {
			// Only infer JSON schema for JSON-compatible content types
			ct := strings.ToLower(ep.Response.ContentType)
			if ct == "" || strings.Contains(ct, "json") {
				schema := InferSchema(ep.Response.Body)
				if schema != nil {
					response.Content = openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: schema,
						},
					}
				}
			}
		}

		ref := &openapi3.ResponseRef{Value: response}
		seenStatus[statusCode] = ref
		operation.Responses.Set(statusCode, ref)
	}

	// Remove empty default response if we have real responses
	if operation.Responses != nil && operation.Responses.Len() > 0 {
		// Check if default exists
		if defaultResp := operation.Responses.Value("default"); defaultResp != nil {
			// Only remove if it's empty (no description or empty description)
			if defaultResp.Value != nil && (defaultResp.Value.Description == nil || *defaultResp.Value.Description == "") {
				operation.Responses.Delete("default")
			}
		}
	}

	// LAB-2108: x-vespasian-source extension.
	// Only emit when the overall Generate input contained at least one static: source
	// (emitSource=true), preventing any change to output for flag-off/legacy captures.
	if emitSource {
		if src := computeSourceTag(group); src != "" {
			if operation.Extensions == nil {
				operation.Extensions = map[string]any{}
			}
			operation.Extensions["x-vespasian-source"] = src
		}
	}

	return operation
}

// Generate produces an OpenAPI specification.
func (g *OpenAPIGenerator) Generate(endpoints []classify.ClassifiedRequest) ([]byte, error) { //nolint:gocyclo // top-level generation orchestration
	if len(endpoints) == 0 {
		return nil, nil
	}

	// Extract servers and title
	servers, titleHost := extractServers(endpoints)

	// Create OpenAPI document
	doc := &openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   titleHost,
			Version: "1.0.0",
		},
		Paths:   openapi3.NewPaths(),
		Servers: servers,
	}

	// Group and sort endpoints
	endpointGroups := groupEndpoints(endpoints)

	// Determine whether to emit x-vespasian-source extensions.
	// Only emitted when at least one input request has a "static:" Source so that
	// output is byte-identical to pre-LAB-2108 when --analyze-js is not in use.
	staticPresent := anyStaticSource(endpoints)

	// Sort endpoint keys for deterministic output
	keys := make([]endpointKey, 0, len(endpointGroups))
	for k := range endpointGroups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path != keys[j].path {
			return keys[i].path < keys[j].path
		}
		return keys[i].method < keys[j].method
	})

	// Build paths
	for _, key := range keys {
		group := endpointGroups[key]
		pathItem := doc.Paths.Find(key.path)
		if pathItem == nil {
			pathItem = &openapi3.PathItem{}
			doc.Paths.Set(key.path, pathItem)
		}

		// Build operation from group
		operation := buildOperation(key, group, staticPresent)

		// Set operation for the method
		switch key.method {
		case "get":
			pathItem.Get = operation
		case "post":
			pathItem.Post = operation
		case "put":
			pathItem.Put = operation
		case "delete":
			pathItem.Delete = operation
		case "patch":
			pathItem.Patch = operation
		case "head":
			pathItem.Head = operation
		case "options":
			pathItem.Options = operation
		}
	}

	// Extract schemas to components/schemas with $ref references
	extractComponents(doc)

	// Validate the spec
	specBytes, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}

	loader := openapi3.NewLoader()
	_, err = loader.LoadFromData(specBytes)
	if err != nil {
		return nil, err
	}

	// Serialize based on format
	format := g.Format
	if format == "" {
		format = "yaml"
	}

	if format == "json" {
		return json.MarshalIndent(doc, "", "  ")
	}

	// Reuse the already-serialized YAML from validation
	return specBytes, nil
}

// extractPathParams extracts parameter names from a path template like "/users/{userId}/posts/{postId}".
func extractPathParams(path string) []string {
	var params []string
	segments := strings.Split(path, "/")
	for _, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			paramName := strings.TrimPrefix(strings.TrimSuffix(segment, "}"), "{")
			params = append(params, paramName)
		}
	}
	return params
}

// commonPathExtensions are file extensions often seen in web app URLs that should
// not form part of an OpenAPI component name (they're not resource names, they're
// server-side file types).
var commonPathExtensions = map[string]bool{
	".php": true, ".asp": true, ".aspx": true, ".jsp": true, ".mvc": true,
	".html": true, ".htm": true, ".json": true, ".xml": true, ".action": true, ".do": true,
}

// resourceNameFromPath extracts and capitalizes the resource name from an API path.
// It returns the last non-parameterized, non-empty segment as a singular, capitalized word.
// Examples:
//   - "/api/v2/tickets" → "Ticket"
//   - "/api/v2/tickets/{ticketId}" → "Ticket"
//   - "/api/v2/categories/{categoryId}/items/{itemId}" → "Item"
//   - "/api/v2/users/me/settings" → "Setting"
//   - "/login.php" → "Login"
//   - "/stored-xss" → "StoredXss"
func resourceNameFromPath(path string) string {
	segments := strings.Split(path, "/")
	// Walk backwards to find last non-param, non-empty segment
	for i := len(segments) - 1; i >= 0; i-- {
		seg := segments[i]
		if seg == "" || strings.HasPrefix(seg, "{") {
			continue
		}
		return sanitizeResourceName(seg)
	}
	return "Resource"
}

// toCamelCase converts a string to CamelCase by splitting on non-alphanumeric
// characters and capitalizing the first letter of each resulting segment.
//
// Note: this function is ASCII-only by design. Non-ASCII letters (e.g., 'é',
// 'ñ', '日本語') fall through to the separator branch and are dropped from the
// output. OpenAPI component names are conventionally ASCII; if a path segment
// is entirely non-ASCII the result will be empty and resourceNameFromPath
// falls back to "Resource".
func toCamelCase(s string) string {
	var b strings.Builder
	capitalizeNext := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			if capitalizeNext {
				r = r - 'a' + 'A'
			}
			b.WriteRune(r)
			capitalizeNext = false
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			capitalizeNext = false
		default:
			capitalizeNext = true
		}
	}
	return b.String()
}

// sanitizeResourceName turns a path segment into a valid OpenAPI component name
// fragment: strips common file extensions, splits on non-alphanumerics, capitalizes
// and joins each part, then singularizes. Falls back to "Resource" if the segment
// sanitizes to empty.
func sanitizeResourceName(seg string) string {
	lower := strings.ToLower(seg)
	for ext := range commonPathExtensions {
		if strings.HasSuffix(lower, ext) {
			seg = seg[:len(seg)-len(ext)]
			break
		}
	}
	result := toCamelCase(seg)
	if result == "" {
		return "Resource"
	}
	if result[0] >= '0' && result[0] <= '9' {
		return "Resource" + result
	}
	return singularize(result)
}

// schemaFingerprint computes a string fingerprint of a schema for deduplication.
// Returns a sorted, comma-separated list of "propertyName:type" pairs.
func schemaFingerprint(schema *openapi3.Schema) string {
	if schema == nil || schema.Properties == nil {
		return ""
	}
	keys := make([]string, 0, len(schema.Properties))
	for k, v := range schema.Properties {
		t := "unknown"
		if v != nil && v.Value != nil && v.Value.Type != nil && len(v.Value.Type.Slice()) > 0 {
			t = v.Value.Type.Slice()[0]
		}
		keys = append(keys, k+":"+t)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// extractComponents extracts inline schemas to components/schemas with $ref references.
// This is called after all paths are built, before validation.
func extractComponents(doc *openapi3.T) { //nolint:gocyclo // component extraction logic
	// Initialize components if needed
	if doc.Components == nil {
		doc.Components = &openapi3.Components{}
	}
	if doc.Components.Schemas == nil {
		doc.Components.Schemas = make(openapi3.Schemas)
	}

	// Separate fingerprint→name maps for request and response so an echo-style
	// endpoint where the request and response bodies share the same property
	// shape doesn't cause the response to reuse the request's component name
	// (e.g., a response getting tagged `CreateUserRequest`).
	fingerprintToReqName := make(map[string]string)
	fingerprintToRespName := make(map[string]string)
	// Track name collisions — shared across both maps so we never generate
	// two components with the same name (e.g., UserResponse collision).
	nameCounter := make(map[string]int)

	// Helper to ensure unique component name
	ensureUniqueName := func(baseName string) string {
		nameCounter[baseName]++
		if nameCounter[baseName] == 1 {
			return baseName
		}
		return baseName + strconv.Itoa(nameCounter[baseName])
	}

	// Helper to derive status code context for response names
	statusContext := func(statusCode string) string {
		switch statusCode {
		case "200":
			return "Response"
		case "201":
			return "CreatedResponse"
		case "204":
			return "" // No body for 204
		case "400":
			return "BadRequestResponse"
		case "401":
			return "UnauthorizedResponse"
		case "403":
			return "ForbiddenResponse"
		case "404":
			return "NotFoundResponse"
		case "500":
			return "InternalErrorResponse"
		default:
			return statusCode + "Response"
		}
	}

	// Walk all paths and operations in deterministic order so that when multiple
	// paths share a schema fingerprint, the component name (chosen on first encounter)
	// is stable across runs.
	pathsMap := doc.Paths.Map()
	sortedPaths := make([]string, 0, len(pathsMap))
	for p := range pathsMap {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)
	for _, path := range sortedPaths {
		pathItem := doc.Paths.Find(path)
		if pathItem == nil {
			continue
		}

		resourceName := resourceNameFromPath(path)

		operations := []*struct {
			method    string
			operation *openapi3.Operation
		}{
			{"post", pathItem.Post},
			{"put", pathItem.Put},
			{"patch", pathItem.Patch},
			{"get", pathItem.Get},
			{"delete", pathItem.Delete},
			{"head", pathItem.Head},
			{"options", pathItem.Options},
		}

		for _, op := range operations {
			if op.operation == nil {
				continue
			}

			// Extract request body schema
			if op.operation.RequestBody != nil && op.operation.RequestBody.Value != nil {
				reqBody := op.operation.RequestBody.Value
				ctKeys := make([]string, 0, len(reqBody.Content))
				for k := range reqBody.Content {
					ctKeys = append(ctKeys, k)
				}
				sort.Strings(ctKeys)
				for _, ctKey := range ctKeys {
					mediaType := reqBody.Content[ctKey]
					if mediaType == nil || mediaType.Schema == nil {
						continue
					}
					if schema := mediaType.Schema.Value; schema != nil && schema.Properties != nil {
						fingerprint := schemaFingerprint(schema)
						if fingerprint != "" {
							var componentName string
							if existingName, exists := fingerprintToReqName[fingerprint]; exists {
								// Reuse existing request component
								componentName = existingName
							} else {
								// Create new request component
								methodPrefix := ""
								switch op.method {
								case "post":
									methodPrefix = "Create"
								case "put", "patch":
									methodPrefix = "Update"
								}
								baseName := methodPrefix + resourceName + "Request"
								componentName = ensureUniqueName(baseName)
								doc.Components.Schemas[componentName] = &openapi3.SchemaRef{Value: schema}
								fingerprintToReqName[fingerprint] = componentName
							}
							// Replace inline schema with $ref
							mediaType.Schema = &openapi3.SchemaRef{
								Ref: "#/components/schemas/" + componentName,
							}
						}
					}
				}
			}

			// Extract response schemas
			if op.operation.Responses != nil {
				sortedStatusCodes := make([]string, 0, op.operation.Responses.Len())
				for statusCode := range op.operation.Responses.Map() {
					sortedStatusCodes = append(sortedStatusCodes, statusCode)
				}
				sort.Strings(sortedStatusCodes)
				for _, statusCode := range sortedStatusCodes {
					respRef := op.operation.Responses.Value(statusCode)
					if respRef == nil || respRef.Value == nil {
						continue
					}
					response := respRef.Value
					respCtKeys := make([]string, 0, len(response.Content))
					for k := range response.Content {
						respCtKeys = append(respCtKeys, k)
					}
					sort.Strings(respCtKeys)
					for _, respCtKey := range respCtKeys {
						mediaType := response.Content[respCtKey]
						if mediaType == nil || mediaType.Schema == nil {
							continue
						}
						if schema := mediaType.Schema.Value; schema != nil && schema.Properties != nil {
							fingerprint := schemaFingerprint(schema)
							if fingerprint != "" {
								var componentName string
								if existingName, exists := fingerprintToRespName[fingerprint]; exists {
									// Reuse existing response component
									componentName = existingName
								} else {
									// Create new response component
									suffix := statusContext(statusCode)
									if suffix == "" {
										continue // Skip 204 No Content
									}
									baseName := resourceName + suffix
									componentName = ensureUniqueName(baseName)
									doc.Components.Schemas[componentName] = &openapi3.SchemaRef{Value: schema}
									fingerprintToRespName[fingerprint] = componentName
								}
								// Replace inline schema with $ref
								mediaType.Schema = &openapi3.SchemaRef{
									Ref: "#/components/schemas/" + componentName,
								}
							}
						}
					}
				}
			}
		}
	}

	// Remove empty components section
	if len(doc.Components.Schemas) == 0 {
		doc.Components = nil
	}
}

// DefaultExtension returns the default file extension.
func (g *OpenAPIGenerator) DefaultExtension() string {
	return ".yaml"
}
