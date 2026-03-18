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
	"regexp"
	"sort"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// operationRe matches GraphQL operation declarations (query/mutation/subscription OperationName).
var operationRe = regexp.MustCompile(`^\s*(query|mutation|subscription)\s+(\w+)`)

// graphqlBody represents a parsed GraphQL request body.
type graphqlBody struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

// inferredOperation holds an inferred GraphQL operation.
type inferredOperation struct {
	OpType     string            // "query", "mutation", or "subscription"
	Name       string            // operation name
	Args       map[string]string // variable name -> inferred type
	ReturnType string            // inferred return type name
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
	seen := make(map[string]bool) // deduplicate by operation name

	for _, ep := range endpoints {
		if ep.APIType != "graphql" {
			continue
		}

		body := parseGraphQLBody(ep.Body)
		if body == nil {
			continue
		}

		opType, opName := extractOperationInfo(body.Query)
		if opName == "" {
			anonCounter++
			opName = fmt.Sprintf("Anonymous%d", anonCounter)
		}
		if opType == "" {
			opType = "query"
		}

		if seen[opName] {
			continue
		}
		seen[opName] = true

		// Infer argument types from variables
		args := make(map[string]string)
		for k, v := range body.Variables {
			args[k] = inferTypeFromValue(v)
		}

		// Infer return type from response
		returnTypeName := opName + "Response"
		responseFields := inferFieldsFromResponse(ep.Response.Body, opName)
		if len(responseFields) > 0 {
			syntheticTypes[returnTypeName] = &inferredType{
				Name:   returnTypeName,
				Fields: responseFields,
			}
		}

		ops = append(ops, inferredOperation{
			OpType:     opType,
			Name:       opName,
			Args:       args,
			ReturnType: returnTypeName,
		})
	}

	if len(ops) == 0 {
		return nil, errors.New("no GraphQL operations found in traffic")
	}

	// Sort operations by name for deterministic output
	sort.Slice(ops, func(i, j int) bool {
		return ops[i].Name < ops[j].Name
	})

	var sb strings.Builder
	sb.WriteString("# Inferred from observed traffic (introspection disabled)\n")

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
			sb.WriteString(op.Name)
			if len(op.Args) > 0 {
				sb.WriteString("(")
				writeArgs(&sb, op.Args)
				sb.WriteString(")")
			}
			fmt.Fprintf(&sb, ": %s\n", op.ReturnType)
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

		// Sort fields for determinism
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

// extractOperationInfo extracts the operation type and name from a GraphQL query string.
func extractOperationInfo(query string) (opType, opName string) {
	matches := operationRe.FindStringSubmatch(query)
	if len(matches) >= 3 {
		return matches[1], matches[2]
	}
	return "", ""
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

// inferFieldsFromResponse parses a GraphQL JSON response and extracts field types
// from data.<operationName> or data.<firstKey>.
func inferFieldsFromResponse(body []byte, opName string) map[string]string {
	if len(body) == 0 {
		return nil
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil
	}

	data, ok := envelope["data"]
	if !ok {
		return nil
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}

	// Try operation name first, then first key
	var responseObj map[string]interface{}
	if obj, ok := dataMap[opName]; ok {
		responseObj, _ = obj.(map[string]interface{})
	}
	if responseObj == nil {
		// Use first key
		for _, v := range dataMap {
			responseObj, _ = v.(map[string]interface{})
			break
		}
	}

	if responseObj == nil {
		return nil
	}

	fields := make(map[string]string)
	for k, v := range responseObj {
		fields[k] = inferTypeFromValue(v)
	}
	return fields
}
