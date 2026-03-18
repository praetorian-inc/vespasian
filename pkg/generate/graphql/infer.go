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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// graphqlBody represents a parsed GraphQL request body.
type graphqlBody struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

// inferredOperation holds an inferred GraphQL operation.
type inferredOperation struct {
	OpType     string            // "query", "mutation", or "subscription"
	FieldName  string            // root field name from the selection set
	Args       map[string]string // argument name -> type
	ReturnType string            // inferred return type name
	IsList     bool              // whether the return type is a list
}

// inferredType holds a synthetic type inferred from response data.
type inferredType struct {
	Name   string
	Fields map[string]string // field name -> type string
}

// inferSDL produces a partial SDL from observed GraphQL traffic.
func inferSDL(endpoints []classify.ClassifiedRequest) ([]byte, error) {
	var ops []inferredOperation
	syntheticTypes := make(map[string]*inferredType)
	anonCounter := 0
	seen := make(map[string]bool) // deduplicate by root field name

	for _, ep := range endpoints {
		if ep.APIType != "graphql" {
			continue
		}

		body := parseGraphQLBody(ep.Body)
		if body == nil {
			continue
		}

		parsed := parseQueryAST(body.Query)
		if parsed == nil {
			continue
		}

		opType := astOpTypeToString(parsed.opType)
		fieldName := parsed.rootFieldName
		if fieldName == "" {
			anonCounter++
			fieldName = fmt.Sprintf("anonymous%d", anonCounter)
		}

		if seen[fieldName] {
			continue
		}
		seen[fieldName] = true

		// Build argument types: prefer AST variable definitions mapped through arguments
		args := buildArgTypes(parsed, body.Variables)

		// Infer return type from response, using root field name to locate data
		returnTypeName := upperFirst(fieldName) + "Response"
		responseFields, isList := inferFieldsFromResponse(ep.Response.Body, fieldName, parsed.selectionFields)
		if len(responseFields) > 0 {
			syntheticTypes[returnTypeName] = &inferredType{
				Name:   returnTypeName,
				Fields: responseFields,
			}
		}

		ops = append(ops, inferredOperation{
			OpType:     opType,
			FieldName:  fieldName,
			Args:       args,
			ReturnType: returnTypeName,
			IsList:     isList,
		})
	}

	if len(ops) == 0 {
		return nil, errors.New("no GraphQL operations found in traffic")
	}

	// Sort operations by field name for deterministic output
	sort.Slice(ops, func(i, j int) bool {
		return ops[i].FieldName < ops[j].FieldName
	})

	var sb strings.Builder
	sb.WriteString("# Inferred from observed traffic\n")

	// Group operations by type
	grouped := make(map[string][]inferredOperation)
	for _, op := range ops {
		grouped[op.OpType] = append(grouped[op.OpType], op)
	}

	// Emit operation types in canonical order
	for _, opType := range []string{"query", "mutation", "subscription"} {
		groupOps, ok := grouped[opType]
		if !ok {
			continue
		}

		typeName := strings.ToUpper(opType[:1]) + opType[1:]
		fmt.Fprintf(&sb, "\ntype %s {\n", typeName)
		for _, op := range groupOps {
			sb.WriteString("  ")
			sb.WriteString(op.FieldName)
			if len(op.Args) > 0 {
				sb.WriteString("(")
				writeArgs(&sb, op.Args)
				sb.WriteString(")")
			}
			returnType := op.ReturnType
			if op.IsList {
				returnType = "[" + returnType + "]"
			}
			fmt.Fprintf(&sb, ": %s\n", returnType)
		}
		sb.WriteString("}\n")
	}

	// Emit synthetic return types sorted by name
	var typeNames []string
	for name := range syntheticTypes {
		typeNames = append(typeNames, name)
	}
	sort.Strings(typeNames)

	for _, name := range typeNames {
		st := syntheticTypes[name]
		fmt.Fprintf(&sb, "\ntype %s {\n", st.Name)

		var fieldNames []string
		for fn := range st.Fields {
			fieldNames = append(fieldNames, fn)
		}
		sort.Strings(fieldNames)

		for _, fn := range fieldNames {
			fmt.Fprintf(&sb, "  %s: %s\n", fn, st.Fields[fn])
		}
		sb.WriteString("}\n")
	}

	return []byte(sb.String()), nil
}

// parsedQuery holds the results of parsing a GraphQL query string with gqlparser.
type parsedQuery struct {
	opType          ast.Operation
	opName          string
	rootFieldName   string
	rootFieldArgs   []*ast.Argument // arguments on the root field
	varDefs         ast.VariableDefinitionList
	selectionFields []string // field names from the root field's selection set
}

// parseQueryAST parses a GraphQL query string and extracts operation info.
func parseQueryAST(query string) *parsedQuery {
	doc, parseErr := parser.ParseQuery(&ast.Source{Input: query})
	if parseErr != nil || len(doc.Operations) == 0 {
		return nil
	}

	op := doc.Operations[0]
	result := &parsedQuery{
		opType:  op.Operation,
		opName:  op.Name,
		varDefs: op.VariableDefinitions,
	}

	// Extract root field name and its selection set from the first field in the operation
	if len(op.SelectionSet) > 0 {
		if field, ok := op.SelectionSet[0].(*ast.Field); ok {
			result.rootFieldName = field.Name
			result.rootFieldArgs = field.Arguments
			for _, sel := range field.SelectionSet {
				if subField, ok := sel.(*ast.Field); ok {
					result.selectionFields = append(result.selectionFields, subField.Name)
				}
			}
		}
	}

	return result
}

// astOpTypeToString converts an ast.Operation to a string.
func astOpTypeToString(op ast.Operation) string {
	switch op {
	case ast.Mutation:
		return "mutation"
	case ast.Subscription:
		return "subscription"
	default:
		return "query"
	}
}

// astTypeToSDL converts a gqlparser AST type to its SDL string representation.
func astTypeToSDL(t *ast.Type) string {
	if t == nil {
		return "String"
	}
	var base string
	if t.Elem != nil {
		// List type
		base = "[" + astTypeToSDL(t.Elem) + "]"
	} else {
		base = t.NamedType
		if base == "" {
			base = "String"
		}
	}
	if t.NonNull {
		base += "!"
	}
	return base
}

// buildArgTypes builds argument type mappings. It prefers declared variable types from the AST,
// falling back to JSON value inference for variables not declared in the query.
func buildArgTypes(parsed *parsedQuery, variables map[string]interface{}) map[string]string {
	args := make(map[string]string)

	// Build a map from variable name to its declared type
	varTypes := make(map[string]string)
	for _, vd := range parsed.varDefs {
		varTypes[vd.Variable] = astTypeToSDL(vd.Type)
	}

	// Map root field arguments: arg name -> type from the variable it references
	for _, arg := range parsed.rootFieldArgs {
		argName := arg.Name
		// If the argument value is a variable reference, use the variable's declared type
		if arg.Value != nil && arg.Value.Kind == ast.Variable {
			varName := arg.Value.Raw
			if declaredType, ok := varTypes[varName]; ok {
				args[argName] = declaredType
				continue
			}
			// Fall back to JSON inference for this variable
			if val, ok := variables[varName]; ok {
				args[argName] = inferTypeFromValue(val)
				continue
			}
		}
		// Default fallback
		args[argName] = "String"
	}

	// If no root field arguments were extracted but we have variables, use them directly
	if len(args) == 0 {
		for varName, varType := range varTypes {
			args[varName] = varType
		}
		// For variables not declared in the query, infer from JSON values
		for k, v := range variables {
			if _, exists := args[k]; !exists {
				args[k] = inferTypeFromValue(v)
			}
		}
	}

	return args
}

// writeArgs writes sorted argument definitions.
func writeArgs(sb *strings.Builder, args map[string]string) {
	var names []string
	for k := range args {
		names = append(names, k)
	}
	sort.Strings(names)

	for i, name := range names {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(sb, "%s: %s", name, args[name])
	}
}

// parseGraphQLBody parses a JSON request body as a GraphQL operation.
func parseGraphQLBody(body []byte) *graphqlBody {
	if len(body) == 0 {
		return nil
	}
	var gb graphqlBody
	if err := json.Unmarshal(body, &gb); err != nil {
		return nil
	}
	if gb.Query == "" {
		return nil
	}
	return &gb
}

// inferTypeFromValue infers a GraphQL type from a JSON value.
func inferTypeFromValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return "String"
	case bool:
		return "Boolean"
	case float64:
		if val == math.Trunc(val) {
			return "Int"
		}
		return "Float"
	case nil:
		return "String"
	default:
		return "String"
	}
}

// inferFieldsFromResponse parses a GraphQL JSON response and extracts field types.
// It uses the root field name to locate the data, handles array responses,
// and uses selectionFields to guide which fields to include.
// Returns the fields map and whether the response value was an array.
func inferFieldsFromResponse(body []byte, rootFieldName string, selectionFields []string) (map[string]string, bool) {
	if len(body) == 0 {
		return nil, false
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false
	}

	data, ok := envelope["data"]
	if !ok {
		return nil, false
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, false
	}

	// Look up the root field by name, then fall back to first key
	responseVal, ok := dataMap[rootFieldName]
	if !ok {
		for _, v := range dataMap {
			responseVal = v
			break
		}
	}

	if responseVal == nil {
		return nil, false
	}

	// Handle array responses: inspect the first element
	isList := false
	var responseObj map[string]interface{}
	switch rv := responseVal.(type) {
	case []interface{}:
		isList = true
		if len(rv) > 0 {
			responseObj, _ = rv[0].(map[string]interface{})
		}
	case map[string]interface{}:
		responseObj = rv
	}

	if responseObj == nil {
		return nil, isList
	}

	fields := make(map[string]string)

	// If we have selection fields from the query AST, use them as the authoritative field list
	if len(selectionFields) > 0 {
		for _, fieldName := range selectionFields {
			if v, ok := responseObj[fieldName]; ok {
				fields[fieldName] = inferTypeFromValue(v)
			} else {
				fields[fieldName] = "String"
			}
		}
	} else {
		// Fall back to all fields from the response object
		for k, v := range responseObj {
			fields[k] = inferTypeFromValue(v)
		}
	}

	return fields, isList
}

// upperFirst returns the string with its first character uppercased.
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
