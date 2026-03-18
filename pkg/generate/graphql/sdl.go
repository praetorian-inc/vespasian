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

// Package graphql generates GraphQL SDL specifications from classified requests.
package graphql

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// builtinScalars are the built-in GraphQL scalar types that should not be emitted.
var builtinScalars = map[string]bool{
	"String":  true,
	"Int":     true,
	"Float":   true,
	"Boolean": true,
	"ID":      true,
}

// rootTypeNames are the conventional root operation type names.
var rootTypeNames = map[string]bool{
	"Query":        true,
	"Mutation":     true,
	"Subscription": true,
}

// Generator produces GraphQL SDL specifications from classified requests.
type Generator struct{}

// APIType returns the API type this generator supports.
func (g *Generator) APIType() string {
	return "graphql"
}

// DefaultExtension returns the default file extension for GraphQL SDL output.
func (g *Generator) DefaultExtension() string {
	return ".graphql"
}

// Generate produces a GraphQL SDL specification from classified endpoints.
// Phase 1: If any endpoint has introspection data, generate SDL from it.
// Phase 2: Fall back to inferring SDL from observed traffic.
func (g *Generator) Generate(endpoints []classify.ClassifiedRequest) ([]byte, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("no endpoints provided")
	}

	// Phase 1: Use introspection data if available
	for _, ep := range endpoints {
		if ep.GraphQLSchema != nil && ep.GraphQLSchema.IntrospectionEnabled && len(ep.GraphQLSchema.Types) > 0 {
			return generateFromIntrospection(ep.GraphQLSchema)
		}
	}

	// Phase 2: Infer from traffic
	return inferSDL(endpoints)
}

// generateFromIntrospection builds SDL from parsed introspection types.
func generateFromIntrospection(schema *classify.GraphQLIntrospection) ([]byte, error) {
	var sb strings.Builder

	// Collect user-defined types, skip builtins
	var userTypes []classify.GraphQLType
	for _, t := range schema.Types {
		if strings.HasPrefix(t.Name, "__") {
			continue
		}
		if t.Kind == "SCALAR" && builtinScalars[t.Name] {
			continue
		}
		userTypes = append(userTypes, t)
	}

	if len(userTypes) == 0 {
		return nil, errors.New("introspection returned no user-defined types")
	}

	// Sort types by name for deterministic output
	sort.Slice(userTypes, func(i, j int) bool {
		return userTypes[i].Name < userTypes[j].Name
	})

	// Emit schema block if root types are present
	writeSchemaBlock(&sb, userTypes)

	// Emit type definitions
	for i, t := range userTypes {
		if i > 0 || sb.Len() > 0 {
			sb.WriteString("\n")
		}
		writeTypeDefinition(&sb, t)
	}

	return []byte(sb.String()), nil
}

// writeSchemaBlock emits a schema { ... } block if any root types exist.
func writeSchemaBlock(sb *strings.Builder, types []classify.GraphQLType) {
	var roots []string
	rootMap := make(map[string]bool)
	for _, t := range types {
		if rootTypeNames[t.Name] && (t.Kind == "OBJECT") {
			rootMap[t.Name] = true
		}
	}

	// Emit in canonical order
	for _, name := range []string{"Query", "Mutation", "Subscription"} {
		if rootMap[name] {
			roots = append(roots, name)
		}
	}

	if len(roots) == 0 {
		return
	}

	sb.WriteString("schema {\n")
	for _, name := range roots {
		fmt.Fprintf(sb, "  %s: %s\n", strings.ToLower(name), name)
	}
	sb.WriteString("}\n")
}

// writeTypeDefinition emits a single SDL type definition.
func writeTypeDefinition(sb *strings.Builder, t classify.GraphQLType) {
	switch t.Kind {
	case "OBJECT":
		fmt.Fprintf(sb, "type %s {\n", t.Name)
		writeFields(sb, t.Fields)
		sb.WriteString("}\n")
	case "INPUT_OBJECT":
		fmt.Fprintf(sb, "input %s {\n", t.Name)
		writeFields(sb, t.Fields)
		sb.WriteString("}\n")
	case "INTERFACE":
		fmt.Fprintf(sb, "interface %s {\n", t.Name)
		writeFields(sb, t.Fields)
		sb.WriteString("}\n")
	case "ENUM":
		fmt.Fprintf(sb, "enum %s {\n", t.Name)
		for _, f := range t.Fields {
			fmt.Fprintf(sb, "  %s\n", f.Name)
		}
		sb.WriteString("}\n")
	case "UNION":
		fmt.Fprintf(sb, "union %s\n", t.Name)
	case "SCALAR":
		fmt.Fprintf(sb, "scalar %s\n", t.Name)
	}
}

// writeFields emits field definitions for object/input/interface types.
func writeFields(sb *strings.Builder, fields []classify.GraphQLField) {
	for _, f := range fields {
		fmt.Fprintf(sb, "  %s: %s\n", f.Name, typeRefToSDL(f.Type))
	}
}

// typeRefToSDL converts a GraphQLTypeRef to its SDL string representation.
// Handles NON_NULL (Type!), LIST ([Type]), and named types via recursive ofType traversal.
func typeRefToSDL(ref classify.GraphQLTypeRef) string {
	switch ref.Kind {
	case "NON_NULL":
		if ref.OfType != nil {
			return typeRefToSDL(*ref.OfType) + "!"
		}
		return "Unknown!"
	case "LIST":
		if ref.OfType != nil {
			return "[" + typeRefToSDL(*ref.OfType) + "]"
		}
		return "[Unknown]"
	default:
		if ref.Name != nil {
			return *ref.Name
		}
		return "Unknown"
	}
}
