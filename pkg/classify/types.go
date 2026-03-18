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

// Package classify provides API classification for observed HTTP requests.
package classify

import (
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// ClassifiedRequest extends ObservedRequest with classification metadata.
type ClassifiedRequest struct {
	crawl.ObservedRequest
	IsAPI      bool    `json:"is_api"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	APIType    string  `json:"api_type"`

	// Probe-enriched fields (populated by pkg/probe strategies)
	AllowedMethods []string               `json:"allowed_methods,omitempty"`
	ResponseSchema map[string]interface{} `json:"response_schema,omitempty"`

	// WSDLDocument holds a probed WSDL document for SOAP endpoints.
	WSDLDocument []byte `json:"wsdl_document,omitempty"`

	// GraphQLSchema holds the parsed introspection result for GraphQL endpoints.
	// Nil means introspection was not attempted or failed.
	GraphQLSchema *GraphQLIntrospection `json:"graphql_schema,omitempty"`
}

// GraphQLIntrospection holds parsed GraphQL introspection results.
type GraphQLIntrospection struct {
	// IntrospectionEnabled indicates whether the endpoint responded to introspection.
	IntrospectionEnabled bool `json:"introspection_enabled"`
	// Types is the parsed list of types from __schema.types.
	Types []GraphQLType `json:"types,omitempty"`
	// RawResponse stores the raw introspection JSON for downstream generators.
	RawResponse []byte `json:"raw_response,omitempty"`
}

// GraphQLType represents a single type from a GraphQL introspection response.
type GraphQLType struct {
	Name   string         `json:"name"`
	Kind   string         `json:"kind"`
	Fields []GraphQLField `json:"fields,omitempty"`
}

// GraphQLField represents a field on a GraphQL type.
type GraphQLField struct {
	Name string         `json:"name"`
	Type GraphQLTypeRef `json:"type"`
}

// GraphQLTypeRef represents a type reference (name + kind + ofType for wrapping types).
type GraphQLTypeRef struct {
	Name   *string         `json:"name"`
	Kind   string          `json:"kind"`
	OfType *GraphQLTypeRef `json:"ofType,omitempty"`
}
