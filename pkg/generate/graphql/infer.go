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
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/url"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/praetorian-inc/vespasian/pkg/classify"
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
	OpName     string            // original operation name from the query
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
	seen := make(map[string]bool) // deduplicate by composite key (opType:fieldName:opName)

	for _, ep := range endpoints {
		if op, ok := processEndpoint(ep, seen, &anonCounter, syntheticTypes); ok {
			ops = append(ops, op)
		}
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

	// Disambiguate field name collisions within each operation type
	for opType, groupOps := range grouped {
		fieldCount := make(map[string]int)
		for _, op := range groupOps {
			fieldCount[op.FieldName]++
		}

		fieldSeen := make(map[string]bool)
		for i, op := range groupOps {
			if fieldCount[op.FieldName] > 1 {
				if !fieldSeen[op.FieldName] {
					// First occurrence keeps the bare name
					fieldSeen[op.FieldName] = true
				} else {
					// Subsequent occurrences get a suffix from the operation name
					suffix := op.OpName
					if suffix == "" {
						suffix = fmt.Sprintf("variant%d", i)
					}
					newFieldName := op.FieldName + "_" + suffix
					newReturnType := upperFirst(newFieldName) + "Response"
					// Update the synthetic type name if it exists
					if st, ok := syntheticTypes[op.ReturnType]; ok {
						delete(syntheticTypes, op.ReturnType)
						st.Name = newReturnType
						syntheticTypes[newReturnType] = st
					}
					groupOps[i].FieldName = newFieldName
					groupOps[i].ReturnType = newReturnType
				}
			}
		}
		grouped[opType] = groupOps
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

// processEndpoint processes a single classified endpoint and returns an inferred operation.
func processEndpoint(ep classify.ClassifiedRequest, seen map[string]bool, anonCounter *int, syntheticTypes map[string]*inferredType) (inferredOperation, bool) {
	if ep.APIType != "graphql" {
		return inferredOperation{}, false
	}

	body := parseGraphQLBody(ep.Body)
	if body == nil {
		body = parseGraphQLURL(ep.URL)
	}
	if body == nil {
		if ct := getContentType(ep.Headers); strings.Contains(ct, "multipart") {
			body = parseGraphQLMultipart(ep.Body, ct)
		}
	}
	if body == nil {
		return inferredOperation{}, false
	}

	parsed := parseQueryAST(body.Query)
	if parsed == nil {
		return inferredOperation{}, false
	}

	opType := astOpTypeToString(parsed.opType)
	fieldName := parsed.rootFieldName
	if fieldName == "" {
		fieldName = lowerFirst(parsed.opName)
	}
	if fieldName == "" {
		*anonCounter++
		fieldName = fmt.Sprintf("anonymous%d", *anonCounter)
	}

	// Deduplicate by composite key incorporating operation name
	dedupKey := opType + ":" + fieldName + ":" + parsed.opName
	if seen[dedupKey] {
		return inferredOperation{}, false
	}
	seen[dedupKey] = true

	args := buildArgTypes(parsed, body.Variables)

	returnTypeName := upperFirst(fieldName) + "Response"
	responseFields, isList := inferFieldsFromResponse(ep.Response.Body, fieldName, parsed.selectionFields)
	if len(responseFields) > 0 {
		syntheticTypes[returnTypeName] = &inferredType{
			Name:   returnTypeName,
			Fields: responseFields,
		}
	}

	return inferredOperation{
		OpType:     opType,
		FieldName:  fieldName,
		OpName:     parsed.opName,
		Args:       args,
		ReturnType: returnTypeName,
		IsList:     isList,
	}, true
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

	// Extract root field name and its selection set, resolving fragment spreads
	if len(op.SelectionSet) > 0 {
		if field := resolveFirstField(op.SelectionSet, doc.Fragments); field != nil {
			result.rootFieldName = field.Name
			result.rootFieldArgs = field.Arguments
			result.selectionFields = collectSelectionFields(field.SelectionSet, doc.Fragments)
		}
	}

	return result
}

// resolveFirstField walks a selection set to find the first concrete *ast.Field,
// resolving fragment spreads and inline fragments as needed.
func resolveFirstField(selections ast.SelectionSet, fragments ast.FragmentDefinitionList) *ast.Field {
	for _, sel := range selections {
		switch s := sel.(type) {
		case *ast.Field:
			return s
		case *ast.FragmentSpread:
			if frag := fragments.ForName(s.Name); frag != nil {
				if field := resolveFirstField(frag.SelectionSet, fragments); field != nil {
					return field
				}
			}
		case *ast.InlineFragment:
			if field := resolveFirstField(s.SelectionSet, fragments); field != nil {
				return field
			}
		}
	}
	return nil
}

// collectSelectionFields recursively collects field names from a selection set,
// resolving fragment spreads and inline fragments.
func collectSelectionFields(selections ast.SelectionSet, fragments ast.FragmentDefinitionList) []string {
	var fields []string
	for _, sel := range selections {
		switch s := sel.(type) {
		case *ast.Field:
			fields = append(fields, s.Name)
		case *ast.FragmentSpread:
			if frag := fragments.ForName(s.Name); frag != nil {
				fields = append(fields, collectSelectionFields(frag.SelectionSet, fragments)...)
			}
		case *ast.InlineFragment:
			fields = append(fields, collectSelectionFields(s.SelectionSet, fragments)...)
		}
	}
	return fields
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
	responseObj, isList, ok := unwrapResponseValue(body, rootFieldName)
	if !ok {
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

// unwrapResponseValue parses a GraphQL JSON response envelope, locates the response
// value for the given root field, and unwraps arrays. Returns the response object,
// whether it was a list, and whether a valid object was found.
func unwrapResponseValue(body []byte, rootFieldName string) (map[string]interface{}, bool, bool) {
	if len(body) == 0 {
		return nil, false, false
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false, false
	}

	data, ok := envelope["data"]
	if !ok {
		return nil, false, false
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, false, false
	}

	responseVal, ok := dataMap[rootFieldName]
	if !ok {
		keys := make([]string, 0, len(dataMap))
		for k := range dataMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			responseVal = dataMap[keys[0]]
		}
	}

	if responseVal == nil {
		return nil, false, false
	}

	switch rv := responseVal.(type) {
	case []interface{}:
		if len(rv) > 0 {
			if obj, ok := rv[0].(map[string]interface{}); ok {
				return obj, true, true
			}
		}
		return nil, true, false
	case map[string]interface{}:
		return rv, false, true
	default:
		return nil, false, false
	}
}

// upperFirst returns the string with its first character uppercased.
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// lowerFirst returns the string with its first character lowercased.
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// parseGraphQLURL extracts a GraphQL operation from URL query parameters (GET requests).
func parseGraphQLURL(rawURL string) *graphqlBody {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	query := u.Query().Get("query")
	if query == "" {
		return nil
	}
	gb := &graphqlBody{Query: query}
	if vars := u.Query().Get("variables"); vars != "" {
		_ = json.Unmarshal([]byte(vars), &gb.Variables)
	}
	return gb
}

// parseGraphQLMultipart extracts a GraphQL operation from a multipart form data body.
func parseGraphQLMultipart(body []byte, contentType string) *graphqlBody {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil
	}
	reader := multipart.NewReader(strings.NewReader(string(body)), boundary)
	for {
		part, err := reader.NextPart()
		if err != nil {
			return nil
		}
		if part.FormName() == "operations" {
			data, err := io.ReadAll(part)
			if err != nil {
				return nil
			}
			var gb graphqlBody
			if err := json.Unmarshal(data, &gb); err != nil {
				return nil
			}
			if gb.Query == "" {
				return nil
			}
			return &gb
		}
	}
}

// getContentType returns the Content-Type header value, case-insensitively.
func getContentType(headers map[string]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "content-type") {
			return v
		}
	}
	return ""
}
