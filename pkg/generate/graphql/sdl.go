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

	// Emit schema block using introspection root type names if available
	writeSchemaBlockFromIntrospection(&sb, schema, userTypes)

	// Emit type definitions
	for i, t := range userTypes {
		if i > 0 || sb.Len() > 0 {
			sb.WriteString("\n")
		}
		writeTypeDefinition(&sb, t)
	}

	return []byte(sb.String()), nil
}

// writeSchemaBlockFromIntrospection emits a schema { ... } block using introspection
// root type names when available, falling back to conventional name detection.
func writeSchemaBlockFromIntrospection(sb *strings.Builder, schema *classify.GraphQLIntrospection, types []classify.GraphQLType) {
	// Build a set of type names that actually exist
	typeExists := make(map[string]bool)
	for _, t := range types {
		typeExists[t.Name] = true
	}

	type rootEntry struct {
		op   string
		name string
	}
	var roots []rootEntry

	// Use introspection root type names if available
	if schema.QueryTypeName != "" && typeExists[schema.QueryTypeName] {
		roots = append(roots, rootEntry{"query", schema.QueryTypeName})
	}
	if schema.MutationTypeName != "" && typeExists[schema.MutationTypeName] {
		roots = append(roots, rootEntry{"mutation", schema.MutationTypeName})
	}
	if schema.SubscriptionTypeName != "" && typeExists[schema.SubscriptionTypeName] {
		roots = append(roots, rootEntry{"subscription", schema.SubscriptionTypeName})
	}

	// Fall back to conventional name detection if no root type names from introspection
	if len(roots) == 0 {
		for _, name := range []string{"Query", "Mutation", "Subscription"} {
			if typeExists[name] {
				roots = append(roots, rootEntry{strings.ToLower(name), name})
			}
		}
	}

	if len(roots) == 0 {
		return
	}

	sb.WriteString("schema {\n")
	for _, r := range roots {
		fmt.Fprintf(sb, "  %s: %s\n", r.op, r.name)
	}
	sb.WriteString("}\n")
}

// writeTypeDefinition emits a single SDL type definition.
func writeTypeDefinition(sb *strings.Builder, t classify.GraphQLType) {
	switch t.Kind {
	case "OBJECT":
		if len(t.Interfaces) > 0 {
			names := make([]string, 0, len(t.Interfaces))
			for _, iface := range t.Interfaces {
				if iface.Name != nil {
					names = append(names, *iface.Name)
				}
			}
			if len(names) > 0 {
				fmt.Fprintf(sb, "type %s implements %s {\n", t.Name, strings.Join(names, " & "))
			} else {
				fmt.Fprintf(sb, "type %s {\n", t.Name)
			}
		} else {
			fmt.Fprintf(sb, "type %s {\n", t.Name)
		}
		writeFields(sb, t.Fields)
		sb.WriteString("}\n")
	case "INPUT_OBJECT":
		fmt.Fprintf(sb, "input %s {\n", t.Name)
		writeInputFields(sb, t.InputFields)
		sb.WriteString("}\n")
	case "INTERFACE":
		fmt.Fprintf(sb, "interface %s {\n", t.Name)
		writeFields(sb, t.Fields)
		sb.WriteString("}\n")
	case "ENUM":
		fmt.Fprintf(sb, "enum %s {\n", t.Name)
		if len(t.EnumValues) > 0 {
			for _, ev := range t.EnumValues {
				fmt.Fprintf(sb, "  %s\n", ev.Name)
			}
		} else {
			// Fall back to field names for Tier 3 responses
			for _, f := range t.Fields {
				fmt.Fprintf(sb, "  %s\n", f.Name)
			}
		}
		sb.WriteString("}\n")
	case "UNION":
		if len(t.PossibleTypes) > 0 {
			names := make([]string, 0, len(t.PossibleTypes))
			for _, pt := range t.PossibleTypes {
				if pt.Name != nil {
					names = append(names, *pt.Name)
				}
			}
			fmt.Fprintf(sb, "union %s = %s\n", t.Name, strings.Join(names, " | "))
		} else {
			fmt.Fprintf(sb, "union %s\n", t.Name)
		}
	case "SCALAR":
		fmt.Fprintf(sb, "scalar %s\n", t.Name)
	}
}

// writeFields emits field definitions with arguments for object/interface types.
func writeFields(sb *strings.Builder, fields []classify.GraphQLField) {
	for _, f := range fields {
		if len(f.Args) > 0 {
			fmt.Fprintf(sb, "  %s(%s): %s\n", f.Name, formatArgs(f.Args), typeRefToSDL(f.Type))
		} else {
			fmt.Fprintf(sb, "  %s: %s\n", f.Name, typeRefToSDL(f.Type))
		}
	}
}

// writeInputFields emits input field definitions.
func writeInputFields(sb *strings.Builder, fields []classify.GraphQLInputValue) {
	for _, f := range fields {
		fmt.Fprintf(sb, "  %s: %s\n", f.Name, typeRefToSDL(f.Type))
	}
}

// formatArgs formats a list of input values as SDL argument syntax.
func formatArgs(args []classify.GraphQLInputValue) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, fmt.Sprintf("%s: %s", a.Name, typeRefToSDL(a.Type)))
	}
	return strings.Join(parts, ", ")
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
