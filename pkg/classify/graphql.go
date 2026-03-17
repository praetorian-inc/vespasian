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
	"encoding/json"
	"net/url"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// Confidence scores for GraphQL classification signals.
const (
	GraphQLPathConfidence      = 0.70 // Path contains /graphql
	GraphQLBodyConfidence      = 0.85 // Request body has query/mutation field
	GraphQLResponseConfidence  = 0.80 // Response has data/errors top-level keys
	GraphQLFullMatchConfidence = 0.95 // Path + body signals combined
)

// graphqlResponseContentTypes lists content types that may carry GraphQL responses.
var graphqlResponseContentTypes = []string{
	"application/json",
	"application/graphql+json",
	"application/graphql-response+json",
}

// GraphQLClassifier classifies GraphQL API requests using ordered heuristic rules.
type GraphQLClassifier struct{}

// Name returns the classifier name.
func (c *GraphQLClassifier) Name() string {
	return "graphql"
}

// Classify determines if the request is a GraphQL API call.
func (c *GraphQLClassifier) Classify(req crawl.ObservedRequest) (bool, float64) {
	isAPI, confidence, _ := c.ClassifyDetail(req)
	return isAPI, confidence
}

// ClassifyDetail returns classification result with a detailed reason string.
//
// Signals applied in order, taking max confidence (not additive):
//  1. Static asset exclusion → (false, 0, "")
//  2. Path contains /graphql → confidence 0.70
//  3. Request body has GraphQL query structure (POST only) → confidence 0.85
//     If path also matched → confidence 0.95
//  4. Response has data/errors top-level keys → confidence max(current, 0.80)
func (c *GraphQLClassifier) ClassifyDetail(req crawl.ObservedRequest) (bool, float64, string) {
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return false, 0, ""
	}

	lowerPath := strings.ToLower(parsedURL.Path)

	// Rule 1: Static asset exclusion.
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return false, 0, ""
		}
	}

	var confidence float64
	var reason string
	pathMatched := false

	// Rule 2: Path heuristic.
	if strings.Contains(lowerPath, "/graphql") {
		confidence = GraphQLPathConfidence
		reason = "graphql-path"
		pathMatched = true
	}

	// Rule 3: Request body analysis (POST only).
	if strings.EqualFold(req.Method, "POST") && len(req.Body) > 0 {
		if b, ok := firstNonSpace(req.Body); ok && b == '{' {
			if hasGraphQLBody(req.Body) {
				if pathMatched {
					confidence = GraphQLFullMatchConfidence
					reason = "graphql-path+graphql-body"
				} else {
					if confidence < GraphQLBodyConfidence {
						confidence = GraphQLBodyConfidence
					}
					if reason == "" {
						reason = "graphql-body"
					} else {
						reason += "+graphql-body"
					}
				}
			}
		}
	}

	// Rule 4: Response structure — only boosts when another signal already matched.
	if confidence > 0 && len(req.Response.Body) > 0 && hasGraphQLContentType(req.Response) {
		if hasGraphQLResponseStructure(req.Response.Body) {
			if confidence < GraphQLResponseConfidence {
				confidence = GraphQLResponseConfidence
			}
			reason += "+graphql-response"
		}
	}

	return confidence > 0, confidence, reason
}

// hasGraphQLBody checks if the request body contains a GraphQL query structure.
// It looks for a "query" field whose value starts with GraphQL syntax.
func hasGraphQLBody(body []byte) bool {
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return false
	}

	queryVal, ok := obj["query"]
	if !ok {
		return false
	}

	queryStr, ok := queryVal.(string)
	if !ok {
		return false
	}

	return looksLikeGraphQL(queryStr)
}

// looksLikeGraphQL checks if a query string value contains GraphQL syntax
// rather than a plain search string.
func looksLikeGraphQL(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false
	}

	// GraphQL queries typically start with these tokens or an opening brace.
	prefixes := []string{"{", "query", "mutation", "subscription", "fragment"}
	lower := strings.ToLower(trimmed)
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}

	// Fallback: if the string contains a brace, it likely has GraphQL syntax.
	return strings.ContainsRune(trimmed, '{')
}

// hasGraphQLContentType checks if the response has a JSON-compatible content type
// that could carry a GraphQL response.
func hasGraphQLContentType(resp crawl.ObservedResponse) bool {
	ct := strings.ToLower(resp.ContentType)
	if ct == "" {
		for k, v := range resp.Headers {
			if strings.EqualFold(k, "content-type") {
				ct = strings.ToLower(v)
				break
			}
		}
	}
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}

	for _, allowed := range graphqlResponseContentTypes {
		if ct == allowed {
			return true
		}
	}
	return false
}

// hasGraphQLResponseStructure checks if the response body is a JSON object
// with "data" or "errors" as top-level keys (standard GraphQL response shape).
func hasGraphQLResponseStructure(body []byte) bool {
	b, ok := firstNonSpace(body)
	if !ok || b != '{' {
		return false
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return false
	}

	_, hasData := obj["data"]
	_, hasErrors := obj["errors"]
	return hasData || hasErrors
}
