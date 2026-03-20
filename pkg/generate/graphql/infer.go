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
	OpType         string            // "query", "mutation", or "subscription"
	FieldName      string            // root field name from the selection set
	OpName         string            // original operation name from the query
	Args           map[string]string // argument name -> type
	ReturnType     string            // inferred return type name
	IsList         bool              // whether the return type is a list
	ResponseFields map[string]string // fields for the root synthetic type
}

// inferredType holds a synthetic type inferred from response data.
type inferredType struct {
	Name      string
	Fields    map[string]string            // field name -> type string
	FieldArgs map[string]map[string]string // field name -> (arg name -> arg type)
}

// inferSDL produces a partial SDL from observed GraphQL traffic.
func inferSDL(endpoints []classify.ClassifiedRequest) ([]byte, error) {
	var ops []inferredOperation
	syntheticTypes := make(map[string]*inferredType)
	syntheticInputTypes := make(map[string]*inferredType)
	syntheticUnions := make(map[string][]string) // union name -> member type names
	anonCounter := 0
	seen := make(map[string]bool) // deduplicate by composite key (opType:fieldName:opName)

	for _, ep := range endpoints {
		if epOps, ok := processEndpoint(ep, seen, &anonCounter, syntheticTypes, syntheticInputTypes, syntheticUnions); ok {
			ops = append(ops, epOps...)
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

	// Merge operations with the same root field name within each operation type
	for opType, groupOps := range grouped {
		merged := make(map[string]*inferredOperation) // fieldName -> merged op
		var order []string                             // preserve first-seen order

		for i := range groupOps {
			op := &groupOps[i]
			if existing, ok := merged[op.FieldName]; ok {
				// Merge args: prefer more specific types over String
				if existing.Args == nil {
					existing.Args = make(map[string]string)
				}
				for k, v := range op.Args {
					if existingType, exists := existing.Args[k]; !exists {
						existing.Args[k] = v
					} else if isMoreSpecificType(v, existingType) {
						existing.Args[k] = v
					}
				}
				// Merge response fields: prefer more specific types
				if existing.ResponseFields == nil {
					existing.ResponseFields = make(map[string]string)
				}
				for k, v := range op.ResponseFields {
					if existingType, exists := existing.ResponseFields[k]; !exists {
						existing.ResponseFields[k] = v
					} else if isMoreSpecificType(v, existingType) {
						existing.ResponseFields[k] = v
					}
				}
				// Upgrade to list if any operation shows it as a list
				if op.IsList {
					existing.IsList = true
				}
			} else {
				merged[op.FieldName] = op
				order = append(order, op.FieldName)
			}
		}

		// Rebuild groupOps from merged map in original order
		var mergedOps []inferredOperation
		for _, name := range order {
			mergedOps = append(mergedOps, *merged[name])
		}
		grouped[opType] = mergedOps
	}

	// Create root synthetic types from merged operations
	for _, groupOps := range grouped {
		for _, op := range groupOps {
			// Skip union return types — they don't need a plain type definition
			if _, isUnion := syntheticUnions[op.ReturnType]; isUnion {
				continue
			}
			fields := op.ResponseFields
			if fields == nil {
				fields = make(map[string]string)
			}
			if existing, ok := syntheticTypes[op.ReturnType]; ok {
				// Merge fields into existing type: prefer more specific types
				for k, v := range fields {
					if existingType, exists := existing.Fields[k]; !exists {
						existing.Fields[k] = v
					} else if isMoreSpecificType(v, existingType) {
						existing.Fields[k] = v
					}
				}
			} else {
				syntheticTypes[op.ReturnType] = &inferredType{
					Name:      op.ReturnType,
					Fields:    fields,
					FieldArgs: make(map[string]map[string]string),
				}
			}
		}
	}

	// Reconcile type/union name collisions (D2, D6):
	// If a union XResult exists and a type XResponse also exists, merge XResponse fields
	// into the first union member type and remove the empty XResponse.
	for unionName, members := range syntheticUnions {
		// Find the corresponding Response type that may conflict
		// Convention: union is FooResult, response type is FooResponse
		baseName := strings.TrimSuffix(unionName, "Result")
		responseName := baseName + "Response"

		// Check if the Response type name is a union member — if so, keep it
		isUnionMember := false
		for _, m := range members {
			if m == responseName {
				isUnionMember = true
				break
			}
		}

		if responseType, ok := syntheticTypes[responseName]; ok && !isUnionMember {
			// Merge response fields into the first union member type
			if len(members) > 0 && len(responseType.Fields) > 0 {
				firstMember := members[0]
				if memberType, ok := syntheticTypes[firstMember]; ok {
					for k, v := range responseType.Fields {
						if _, exists := memberType.Fields[k]; !exists {
							memberType.Fields[k] = v
						}
					}
				}
			}
			// Remove the conflicting Response type
			delete(syntheticTypes, responseName)
			// Update any ops that reference the Response type to point to the union
			for opType, groupOps := range grouped {
				for i := range groupOps {
					if groupOps[i].ReturnType == responseName {
						groupOps[i].ReturnType = unionName
					}
				}
				grouped[opType] = groupOps
			}
			// Update field references in synthetic types that still point to the deleted Response type
			for _, st := range syntheticTypes {
				for fieldName, fieldType := range st.Fields {
					if fieldType == responseName {
						st.Fields[fieldName] = unionName
					}
					if fieldType == "["+responseName+"]" {
						st.Fields[fieldName] = "[" + unionName + "]"
					}
				}
			}
		}
		// Also remove any type with the same name as the union itself
		delete(syntheticTypes, unionName)
	}

	// Cross-type field type propagation: unify structurally similar types
	unifyStructuralFieldTypes(syntheticTypes)

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
			if st.FieldArgs != nil {
				if args, ok := st.FieldArgs[fn]; ok && len(args) > 0 {
					fmt.Fprintf(&sb, "  %s(", fn)
					writeArgs(&sb, args)
					fmt.Fprintf(&sb, "): %s\n", st.Fields[fn])
					continue
				}
			}
			fmt.Fprintf(&sb, "  %s: %s\n", fn, st.Fields[fn])
		}
		sb.WriteString("}\n")
	}

	// Emit synthetic input types sorted by name
	var inputTypeNames []string
	for name := range syntheticInputTypes {
		inputTypeNames = append(inputTypeNames, name)
	}
	sort.Strings(inputTypeNames)

	for _, name := range inputTypeNames {
		it := syntheticInputTypes[name]
		fmt.Fprintf(&sb, "\ninput %s {\n", it.Name)

		var fieldNames []string
		for fn := range it.Fields {
			fieldNames = append(fieldNames, fn)
		}
		sort.Strings(fieldNames)

		for _, fn := range fieldNames {
			fmt.Fprintf(&sb, "  %s: %s\n", fn, it.Fields[fn])
		}
		sb.WriteString("}\n")
	}

	// Emit synthetic union types sorted by name
	var unionNames []string
	for name := range syntheticUnions {
		unionNames = append(unionNames, name)
	}
	sort.Strings(unionNames)

	for _, name := range unionNames {
		members := syntheticUnions[name]
		fmt.Fprintf(&sb, "\nunion %s = %s\n", name, strings.Join(members, " | "))
	}

	// Emit custom scalar declarations for referenced but undeclared types (e.g., Upload)
	referencedScalars := collectCustomScalars(grouped, syntheticTypes, syntheticInputTypes, syntheticUnions)
	if len(referencedScalars) > 0 {
		sort.Strings(referencedScalars)
		for _, s := range referencedScalars {
			fmt.Fprintf(&sb, "\nscalar %s\n", s)
		}
	}

	return []byte(sb.String()), nil
}

// processEndpoint processes a single classified endpoint and returns inferred operations
// (one per root field in multi-root queries).
func processEndpoint(ep classify.ClassifiedRequest, seen map[string]bool, anonCounter *int, syntheticTypes map[string]*inferredType, syntheticInputTypes map[string]*inferredType, syntheticUnions map[string][]string) ([]inferredOperation, bool) {
	if ep.APIType != "graphql" {
		return nil, false
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
		return nil, false
	}

	parsedQueries := parseQueryAST(body.Query)
	if len(parsedQueries) == 0 {
		return nil, false
	}

	var ops []inferredOperation
	for _, parsed := range parsedQueries {
		op, ok := processParsedQuery(parsed, ep, body, seen, anonCounter, syntheticTypes, syntheticInputTypes, syntheticUnions)
		if ok {
			ops = append(ops, op)
		}
	}

	if len(ops) == 0 {
		return nil, false
	}
	return ops, true
}

// processParsedQuery processes a single parsed query (one root field) from an endpoint.
func processParsedQuery(parsed *parsedQuery, ep classify.ClassifiedRequest, body *graphqlBody, seen map[string]bool, anonCounter *int, syntheticTypes map[string]*inferredType, syntheticInputTypes map[string]*inferredType, syntheticUnions map[string][]string) (inferredOperation, bool) {
	opType := astOpTypeToString(parsed.opType)
	fieldName := parsed.rootFieldName
	if fieldName == "" {
		fieldName = lowerFirst(parsed.opName)
	}
	if fieldName == "" {
		*anonCounter++
		fieldName = fmt.Sprintf("anonymous%d", *anonCounter)
	}

	// Deduplicate by composite key incorporating operation name and selection fingerprint.
	// The fingerprint ensures different queries with the same opName are not collapsed.
	selFP := selectionFingerprint(parsed.selectionFields)
	dedupKey := opType + ":" + fieldName + ":" + parsed.opName + ":" + selFP
	if seen[dedupKey] {
		return inferredOperation{}, false
	}
	seen[dedupKey] = true

	args := buildArgTypes(parsed, body.Variables, syntheticInputTypes)
	inferInputTypes(parsed, body.Variables, syntheticInputTypes)

	// Build variable type map for resolving field argument types
	varTypes := make(map[string]string)
	for _, vd := range parsed.varDefs {
		varTypes[vd.Variable] = astTypeToSDL(vd.Type)
	}

	returnTypeName := upperFirst(fieldName) + "Response"
	typePrefix := upperFirst(fieldName)

	responseObj, isList, responseOK := unwrapResponseValue(ep.Response.Body, fieldName)
	var responseFields map[string]string

	if len(parsed.inlineFragments) >= 1 {
		// Union type inference from inline fragments
		unionName := typePrefix + "Result"
		var memberNames []string

		// Merge all array elements for type inference
		mergedObj := mergeArrayElements(ep.Response.Body, fieldName)
		if mergedObj == nil {
			mergedObj = responseObj
		}

		// Mixed case: merge common (direct) fields into each fragment's selection tree
		if parsed.hasNonFragmentFields && len(parsed.selectionTree) > 0 {
			for i := range parsed.inlineFragments {
				parsed.inlineFragments[i].SelectionTree = mergeSelectionNodes(
					parsed.inlineFragments[i].SelectionTree, parsed.selectionTree,
				)
			}
		}

		for _, frag := range parsed.inlineFragments {
			memberNames = append(memberNames, frag.TypeName)
			fragFields := inferFieldsRecursive(mergedObj, frag.SelectionTree, frag.TypeName, syntheticTypes, varTypes, syntheticInputTypes, frag.TypeName, syntheticUnions)
			if len(fragFields) > 0 {
				if existing, ok := syntheticTypes[frag.TypeName]; ok {
					for k, v := range fragFields {
						if _, exists := existing.Fields[k]; !exists {
							existing.Fields[k] = v
						}
					}
				} else {
					syntheticTypes[frag.TypeName] = &inferredType{
						Name:      frag.TypeName,
						Fields:    fragFields,
						FieldArgs: make(map[string]map[string]string),
					}
				}
			}
		}

		// Merge union members instead of overwriting
		if existingMembers, ok := syntheticUnions[unionName]; ok {
			memberSet := make(map[string]bool)
			for _, m := range existingMembers {
				memberSet[m] = true
			}
			for _, m := range memberNames {
				if !memberSet[m] {
					existingMembers = append(existingMembers, m)
				}
			}
			syntheticUnions[unionName] = existingMembers
		} else {
			syntheticUnions[unionName] = memberNames
		}
		returnTypeName = unionName
	} else if responseOK && responseObj != nil && len(parsed.selectionTree) > 0 {
		responseFields = inferFieldsRecursive(responseObj, parsed.selectionTree, typePrefix, syntheticTypes, varTypes, syntheticInputTypes, returnTypeName, syntheticUnions)
	} else if scalarType, ok := detectScalarReturnType(ep.Response.Body, fieldName); ok {
		returnTypeName = scalarType
	} else if len(parsed.selectionTree) > 0 {
		// Response was null/error but we have selection tree — generate type from selection fields
		responseFields = inferFieldsRecursive(nil, parsed.selectionTree, typePrefix, syntheticTypes, varTypes, syntheticInputTypes, returnTypeName, syntheticUnions)
	} else {
		// Fallback: existing flat inference
		responseFields, isList = inferFieldsFromResponse(ep.Response.Body, fieldName, parsed.selectionFields)
	}
	return inferredOperation{
		OpType:         opType,
		FieldName:      fieldName,
		OpName:         parsed.opName,
		Args:           args,
		ReturnType:     returnTypeName,
		IsList:         isList,
		ResponseFields: responseFields,
	}, true
}

// selectionNode represents a field in a nested selection tree.
type selectionNode struct {
	Name            string
	Aliases         []string             // aliases used for this field in queries (for response data lookup)
	Children        []*selectionNode     // nil = leaf (scalar), non-nil = object with sub-fields
	Arguments       []*ast.Argument      // field-level arguments from the query AST
	InlineFragments []inlineFragmentInfo // inline fragments with type conditions on this sub-field
	HasDirectFields bool                 // true if this field has direct field selections alongside inline fragments
}

// inlineFragmentInfo holds type condition and selection tree from an inline fragment.
type inlineFragmentInfo struct {
	TypeName      string           // the type condition, e.g., "PasteObject"
	SelectionTree []*selectionNode // nested selection tree for this fragment
}

// parsedQuery holds the results of parsing a GraphQL query string with gqlparser.
type parsedQuery struct {
	opType               ast.Operation
	opName               string
	rootFieldName        string
	rootFieldArgs        []*ast.Argument // arguments on the root field
	varDefs              ast.VariableDefinitionList
	selectionFields      []string              // field names from the root field's selection set (flat)
	selectionTree        []*selectionNode      // nested selection tree for recursive type inference
	inlineFragments      []inlineFragmentInfo  // inline fragments with type conditions on root field
	hasNonFragmentFields bool                  // true if root field has direct field selections alongside inline fragments
}

// parseQueryAST parses a GraphQL query string and extracts operation info for all root fields.
func parseQueryAST(query string) []*parsedQuery {
	doc, parseErr := parser.ParseQuery(&ast.Source{Input: query})
	if parseErr != nil || len(doc.Operations) == 0 {
		return nil
	}

	op := doc.Operations[0]

	// Extract all root fields from the selection set
	if len(op.SelectionSet) == 0 {
		return nil
	}

	rootFields := resolveAllFields(op.SelectionSet, doc.Fragments)
	if len(rootFields) == 0 {
		return nil
	}

	// Merge duplicate root fields (e.g., multiple fragment spreads contributing the same
	// field name like "viewer") so all selection sets and arguments are combined.
	rootFields = mergeRootFieldsByName(rootFields)

	var results []*parsedQuery
	for _, field := range rootFields {
		frags := collectInlineFragments(field.SelectionSet, doc.Fragments)
		hasDirect := hasTopLevelFields(field.SelectionSet)
		var tree []*selectionNode
		if len(frags) > 0 && hasDirect {
			// Mixed case: only collect direct fields for selectionTree;
			// type-conditioned content stays in inlineFragments only.
			tree = collectDirectFieldNodes(field.SelectionSet, doc.Fragments)
		} else {
			tree = collectSelectionTree(field.SelectionSet, doc.Fragments)
		}
		result := &parsedQuery{
			opType:               op.Operation,
			opName:               op.Name,
			varDefs:              op.VariableDefinitions,
			rootFieldName:        field.Name,
			rootFieldArgs:        field.Arguments,
			selectionFields:      collectSelectionFields(field.SelectionSet, doc.Fragments),
			selectionTree:        tree,
			inlineFragments:      frags,
			hasNonFragmentFields: hasDirect,
		}
		results = append(results, result)
	}

	return results
}

// resolveAllFields walks a selection set to collect all concrete *ast.Field entries,
// resolving fragment spreads and inline fragments as needed.
func resolveAllFields(selections ast.SelectionSet, fragments ast.FragmentDefinitionList) []*ast.Field {
	var fields []*ast.Field
	for _, sel := range selections {
		switch s := sel.(type) {
		case *ast.Field:
			fields = append(fields, s)
		case *ast.FragmentSpread:
			if frag := fragments.ForName(s.Name); frag != nil {
				fields = append(fields, resolveAllFields(frag.SelectionSet, fragments)...)
			}
		case *ast.InlineFragment:
			fields = append(fields, resolveAllFields(s.SelectionSet, fragments)...)
		}
	}
	return fields
}

// mergeRootFieldsByName groups root fields by name and merges their SelectionSets
// and Arguments. This handles queries where multiple fragment spreads contribute
// different selection sets for the same root field (e.g., "viewer").
func mergeRootFieldsByName(fields []*ast.Field) []*ast.Field {
	seen := make(map[string]int)
	var result []*ast.Field
	for _, f := range fields {
		if idx, ok := seen[f.Name]; ok {
			result[idx].SelectionSet = append(result[idx].SelectionSet, f.SelectionSet...)
			// Union-merge arguments by name
			for _, newArg := range f.Arguments {
				found := false
				for _, ea := range result[idx].Arguments {
					if ea.Name == newArg.Name {
						found = true
						break
					}
				}
				if !found {
					result[idx].Arguments = append(result[idx].Arguments, newArg)
				}
			}
		} else {
			seen[f.Name] = len(result)
			result = append(result, f)
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
			if !isMetaField(s.Name) {
				fields = append(fields, s.Name)
			}
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

// selectionFingerprint returns a deterministic string fingerprint for a set of field names.
// Used to distinguish queries with different selection sets but the same operation name.
func selectionFingerprint(fields []string) string {
	sorted := make([]string, len(fields))
	copy(sorted, fields)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// isMetaField returns true for GraphQL introspection meta-fields like __typename.
func isMetaField(name string) bool {
	return strings.HasPrefix(name, "__")
}

// collectSelectionTree builds a recursive selection tree from an AST selection set.
func collectSelectionTree(selections ast.SelectionSet, fragments ast.FragmentDefinitionList) []*selectionNode {
	// Use ordered dedup: track seen names and their indices
	seen := make(map[string]int)
	var nodes []*selectionNode

	for _, sel := range selections {
		switch s := sel.(type) {
		case *ast.Field:
			if isMetaField(s.Name) {
				continue
			}
			var children []*selectionNode
			var subFrags []inlineFragmentInfo
			hasDirectFields := false
			if len(s.SelectionSet) > 0 {
				// Check if this sub-field has inline fragments (union/interface pattern)
				subFrags = collectInlineFragments(s.SelectionSet, fragments)
				hasDirectFields = hasTopLevelFields(s.SelectionSet)
				if len(subFrags) > 0 && !hasDirectFields {
					// Pure union/interface pattern: don't flatten into children
					children = nil
				} else if len(subFrags) > 0 {
					// Mixed case: only collect direct (non-typed) fields as children.
					// Type-conditioned content stays in InlineFragments only.
					children = collectDirectFieldNodes(s.SelectionSet, fragments)
				} else {
					children = collectSelectionTree(s.SelectionSet, fragments)
				}
			}
			if idx, ok := seen[s.Name]; ok {
				// Merge children into existing node
				if children != nil {
					nodes[idx].Children = mergeSelectionNodes(nodes[idx].Children, children)
				}
				// Merge inline fragments from sub-field
				if len(subFrags) > 0 {
					nodes[idx].InlineFragments = mergeInlineFragments(nodes[idx].InlineFragments, subFrags)
					nodes[idx].HasDirectFields = nodes[idx].HasDirectFields || hasDirectFields
				}
				// Merge arguments: union by argument name
				for _, newArg := range s.Arguments {
					found := false
					for _, existingArg := range nodes[idx].Arguments {
						if existingArg.Name == newArg.Name {
							found = true
							break
						}
					}
					if !found {
						nodes[idx].Arguments = append(nodes[idx].Arguments, newArg)
					}
				}
				// Track alias for response data lookup
				if s.Alias != "" && s.Alias != s.Name {
					nodes[idx].Aliases = appendUnique(nodes[idx].Aliases, s.Alias)
				}
			} else {
				var aliases []string
				if s.Alias != "" && s.Alias != s.Name {
					aliases = []string{s.Alias}
				}
				seen[s.Name] = len(nodes)
				nodes = append(nodes, &selectionNode{
					Name:            s.Name,
					Aliases:         aliases,
					Children:        children,
					Arguments:       s.Arguments,
					InlineFragments: subFrags,
					HasDirectFields: hasDirectFields,
				})
			}
		case *ast.FragmentSpread:
			if frag := fragments.ForName(s.Name); frag != nil {
				fragNodes := collectSelectionTree(frag.SelectionSet, fragments)
				nodes, seen = mergeIntoNodeList(nodes, seen, fragNodes)
			}
		case *ast.InlineFragment:
			inlineNodes := collectSelectionTree(s.SelectionSet, fragments)
			nodes, seen = mergeIntoNodeList(nodes, seen, inlineNodes)
		}
	}

	return nodes
}

// collectInlineFragments extracts inline fragments with type conditions from a selection set.
func collectInlineFragments(selections ast.SelectionSet, fragments ast.FragmentDefinitionList) []inlineFragmentInfo {
	var frags []inlineFragmentInfo
	seen := make(map[string]int) // type name -> index in frags (merge duplicate type conditions)

	for _, sel := range selections {
		switch s := sel.(type) {
		case *ast.InlineFragment:
			if s.TypeCondition != "" {
				tree := collectSelectionTree(s.SelectionSet, fragments)
				if idx, ok := seen[s.TypeCondition]; ok {
					frags[idx].SelectionTree = mergeSelectionNodes(frags[idx].SelectionTree, tree)
				} else {
					seen[s.TypeCondition] = len(frags)
					frags = append(frags, inlineFragmentInfo{
						TypeName:      s.TypeCondition,
						SelectionTree: tree,
					})
				}
			}
		case *ast.FragmentSpread:
			if frag := fragments.ForName(s.Name); frag != nil {
				// Check for nested inline fragments within the named fragment
				nested := collectInlineFragments(frag.SelectionSet, fragments)
				if len(nested) > 0 {
					// Fragment contains type-narrowing inline fragments (e.g., fragment X on Viewer { ... on User { ... } })
					// Extract the nested fragments — the outer fragment is on the parent type, not a union member
					for _, n := range nested {
						if idx, ok := seen[n.TypeName]; ok {
							frags[idx].SelectionTree = mergeSelectionNodes(frags[idx].SelectionTree, n.SelectionTree)
						} else {
							seen[n.TypeName] = len(frags)
							frags = append(frags, n)
						}
					}
					// Also collect direct *ast.Field entries from the fragment body
					// and merge them into the fragment's type condition. This handles
					// fragments that have both nested inline fragments AND direct fields
					// (e.g., fragment Wallet_user on User { ...WalletDashboard_user referFriend { ... } })
					if frag.TypeCondition != "" {
						directTree := collectDirectFieldNodes(frag.SelectionSet, fragments)
						if len(directTree) > 0 {
							if idx, ok := seen[frag.TypeCondition]; ok {
								frags[idx].SelectionTree = mergeSelectionNodes(frags[idx].SelectionTree, directTree)
							} else {
								seen[frag.TypeCondition] = len(frags)
								frags = append(frags, inlineFragmentInfo{
									TypeName:      frag.TypeCondition,
									SelectionTree: directTree,
								})
							}
						}
					}
				} else if frag.TypeCondition != "" {
					// Fragment has no nested inline fragments and has substantive fields —
					// treat it as a typed fragment (e.g., fragment UserFields on User { id profile { bio } }).
					tree := collectSelectionTree(frag.SelectionSet, fragments)
					hasSubstantiveFields := false
					for _, node := range tree {
						if !isMetaField(node.Name) {
							hasSubstantiveFields = true
							break
						}
					}
					if hasSubstantiveFields {
						if idx, ok := seen[frag.TypeCondition]; ok {
							frags[idx].SelectionTree = mergeSelectionNodes(frags[idx].SelectionTree, tree)
						} else {
							seen[frag.TypeCondition] = len(frags)
							frags = append(frags, inlineFragmentInfo{
								TypeName:      frag.TypeCondition,
								SelectionTree: tree,
							})
						}
					}
				}
			}
		}
	}

	return frags
}

// collectDirectFieldNodes extracts only direct *ast.Field entries from a selection set
// (ignoring inline fragments and fragment spreads) and builds them into selection nodes.
// Used to capture sibling fields that appear alongside nested inline fragments.
func collectDirectFieldNodes(selections ast.SelectionSet, fragments ast.FragmentDefinitionList) []*selectionNode {
	var fieldOnly ast.SelectionSet
	for _, sel := range selections {
		if _, ok := sel.(*ast.Field); ok {
			fieldOnly = append(fieldOnly, sel)
		}
	}
	if len(fieldOnly) == 0 {
		return nil
	}
	return collectSelectionTree(fieldOnly, fragments)
}

// hasTopLevelFields returns true if a selection set contains direct field selections
// (not inside inline fragments). Used to distinguish union patterns from interface patterns.
func hasTopLevelFields(selections ast.SelectionSet) bool {
	for _, sel := range selections {
		if f, ok := sel.(*ast.Field); ok && !isMetaField(f.Name) {
			return true
		}
	}
	return false
}

// mergeIntoNodeList merges source nodes into an existing ordered node list with deduplication.
func mergeIntoNodeList(nodes []*selectionNode, seen map[string]int, source []*selectionNode) ([]*selectionNode, map[string]int) {
	for _, sn := range source {
		if idx, ok := seen[sn.Name]; ok {
			if sn.Children != nil {
				nodes[idx].Children = mergeSelectionNodes(nodes[idx].Children, sn.Children)
			}
			// Merge inline fragments from sub-field
			if len(sn.InlineFragments) > 0 {
				nodes[idx].InlineFragments = mergeInlineFragments(nodes[idx].InlineFragments, sn.InlineFragments)
				nodes[idx].HasDirectFields = nodes[idx].HasDirectFields || sn.HasDirectFields
			}
			// Merge arguments: union by argument name
			for _, newArg := range sn.Arguments {
				found := false
				for _, existingArg := range nodes[idx].Arguments {
					if existingArg.Name == newArg.Name {
						found = true
						break
					}
				}
				if !found {
					nodes[idx].Arguments = append(nodes[idx].Arguments, newArg)
				}
			}
			// Merge aliases
			for _, alias := range sn.Aliases {
				nodes[idx].Aliases = appendUnique(nodes[idx].Aliases, alias)
			}
		} else {
			seen[sn.Name] = len(nodes)
			nodes = append(nodes, sn)
		}
	}
	return nodes, seen
}

// mergeSelectionNodes merges two child node slices, deduplicating by name.
func mergeSelectionNodes(a, b []*selectionNode) []*selectionNode {
	seen := make(map[string]int)
	var merged []*selectionNode
	for _, n := range a {
		seen[n.Name] = len(merged)
		merged = append(merged, n)
	}
	for _, n := range b {
		if idx, ok := seen[n.Name]; ok {
			if n.Children != nil {
				merged[idx].Children = mergeSelectionNodes(merged[idx].Children, n.Children)
			}
			// Merge inline fragments from sub-field
			if len(n.InlineFragments) > 0 {
				merged[idx].InlineFragments = mergeInlineFragments(merged[idx].InlineFragments, n.InlineFragments)
				merged[idx].HasDirectFields = merged[idx].HasDirectFields || n.HasDirectFields
			}
			// Merge arguments: union by argument name
			for _, newArg := range n.Arguments {
				found := false
				for _, existingArg := range merged[idx].Arguments {
					if existingArg.Name == newArg.Name {
						found = true
						break
					}
				}
				if !found {
					merged[idx].Arguments = append(merged[idx].Arguments, newArg)
				}
			}
			// Merge aliases
			for _, alias := range n.Aliases {
				merged[idx].Aliases = appendUnique(merged[idx].Aliases, alias)
			}
		} else {
			seen[n.Name] = len(merged)
			merged = append(merged, n)
		}
	}
	return merged
}

// mergeInlineFragments merges two inline fragment lists, deduplicating by type name
// and merging selection trees for duplicate type conditions.
func mergeInlineFragments(a, b []inlineFragmentInfo) []inlineFragmentInfo {
	seen := make(map[string]int)
	var merged []inlineFragmentInfo
	for i, f := range a {
		seen[f.TypeName] = i
		merged = append(merged, f)
	}
	for _, f := range b {
		if idx, ok := seen[f.TypeName]; ok {
			merged[idx].SelectionTree = mergeSelectionNodes(merged[idx].SelectionTree, f.SelectionTree)
		} else {
			seen[f.TypeName] = len(merged)
			merged = append(merged, f)
		}
	}
	return merged
}

// lookupResponseValue looks up a response value by the node's name and any known aliases.
// When multiple keys match (e.g., aliased and non-aliased versions of the same field),
// it prefers the richest value — a non-nil map or non-empty slice over nil/empty ones.
// This ensures aliased fields like `validFareLocks: fareLocks(first:3)` contribute
// their response data for type inference even when a non-aliased empty variant exists.
func lookupResponseValue(responseObj map[string]interface{}, node *selectionNode) (interface{}, bool) {
	var bestVal interface{}
	found := false

	// Check canonical name
	if v, ok := responseObj[node.Name]; ok {
		bestVal = v
		found = true
	}

	// Check aliases, preferring richer values
	for _, alias := range node.Aliases {
		if alias != node.Name {
			if v, ok := responseObj[alias]; ok {
				if !found || isRicherValue(v, bestVal) {
					bestVal = v
					found = true
				}
			}
		}
	}

	return bestVal, found
}

// isRicherValue returns true if candidate provides more type information than current.
// A non-nil map or non-empty slice is richer than nil, a scalar, or an empty collection.
func isRicherValue(candidate, current interface{}) bool {
	if current == nil {
		return candidate != nil
	}
	switch cv := candidate.(type) {
	case map[string]interface{}:
		if cm, ok := current.(map[string]interface{}); ok {
			return len(cv) > len(cm)
		}
		return true // map is richer than scalar/nil
	case []interface{}:
		if ca, ok := current.([]interface{}); ok {
			return len(cv) > len(ca)
		}
		return true // non-empty list is richer than scalar/nil
	}
	return false
}

// appendUnique appends a string to a slice only if it is not already present.
func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

// inferFieldsRecursive walks the selection tree and response JSON together to build
// nested synthetic types. It returns the fields map for the current level.
// parentTypeName identifies the synthetic type being built at this level, so field
// arguments can be stored in its FieldArgs.
func inferFieldsRecursive(
	responseObj map[string]interface{},
	tree []*selectionNode,
	typePrefix string,
	syntheticTypes map[string]*inferredType,
	varTypes map[string]string,
	inputTypes map[string]*inferredType,
	parentTypeName string,
	syntheticUnions map[string][]string,
) map[string]string {
	fields := make(map[string]string)

	for _, node := range tree {
		// Infer field arguments if present
		if len(node.Arguments) > 0 {
			args := inferFieldArgTypes(node.Arguments, varTypes, inputTypes)
			if len(args) > 0 {
				storeFieldArgs(syntheticTypes, parentTypeName, node.Name, args)
			}
		}

		// Sub-field union/interface pattern: inline fragments (with or without direct fields)
		if len(node.InlineFragments) > 0 {
			unionName := typePrefix + "_" + upperFirst(node.Name) + "Result"
			var memberNames []string

			// Extract nested response value for type matching
			var nestedObj map[string]interface{}
			isList := false
			if responseObj != nil {
				if v, ok := lookupResponseValue(responseObj, node); ok {
					switch rv := v.(type) {
					case map[string]interface{}:
						nestedObj = rv
					case []interface{}:
						isList = true
						// Merge all array elements for richer type inference
						nestedObj = mergeArrayElementsRaw(rv)
					}
				}
			}

			// Mixed case: merge common (direct) fields into each fragment's selection tree
			// so union member types include the shared fields alongside their type-specific fields
			if node.HasDirectFields && node.Children != nil {
				for i := range node.InlineFragments {
					node.InlineFragments[i].SelectionTree = mergeSelectionNodes(
						node.InlineFragments[i].SelectionTree, node.Children,
					)
				}
			}

			for _, frag := range node.InlineFragments {
				memberNames = append(memberNames, frag.TypeName)
				fragFields := inferFieldsRecursive(nestedObj, frag.SelectionTree, frag.TypeName, syntheticTypes, varTypes, inputTypes, frag.TypeName, syntheticUnions)
				if len(fragFields) > 0 {
					if existing, ok := syntheticTypes[frag.TypeName]; ok {
						for k, v := range fragFields {
							if _, exists := existing.Fields[k]; !exists {
								existing.Fields[k] = v
							}
						}
					} else {
						syntheticTypes[frag.TypeName] = &inferredType{
							Name:      frag.TypeName,
							Fields:    fragFields,
							FieldArgs: make(map[string]map[string]string),
						}
					}
				}
			}

			// Register union (merge with existing members)
			if existingMembers, ok := syntheticUnions[unionName]; ok {
				memberSet := make(map[string]bool)
				for _, m := range existingMembers {
					memberSet[m] = true
				}
				for _, m := range memberNames {
					if !memberSet[m] {
						existingMembers = append(existingMembers, m)
					}
				}
				syntheticUnions[unionName] = existingMembers
			} else {
				syntheticUnions[unionName] = memberNames
			}

			if isList {
				fields[node.Name] = "[" + unionName + "]"
			} else {
				fields[node.Name] = unionName
			}
			continue
		}

		if node.Children == nil {
			// Leaf node: infer scalar type from response
			if responseObj != nil {
				if v, ok := lookupResponseValue(responseObj, node); ok {
					fields[node.Name] = inferTypeFromValue(v)
					continue
				}
			}
			fields[node.Name] = "String"
			continue
		}

		// Object node: generate nested type
		nestedTypeName := typePrefix + "_" + upperFirst(node.Name) + "Response"

		// Extract nested response value
		var nestedObj map[string]interface{}
		isList := false
		if responseObj != nil {
			if v, ok := lookupResponseValue(responseObj, node); ok {
				switch rv := v.(type) {
				case map[string]interface{}:
					nestedObj = rv
				case []interface{}:
					isList = true
					if len(rv) > 0 {
						if obj, ok := rv[0].(map[string]interface{}); ok {
							nestedObj = obj
						}
					}
				}
			}
		}

		// Recurse to build nested type fields
		nestedFields := inferFieldsRecursive(nestedObj, node.Children, typePrefix+"_"+upperFirst(node.Name), syntheticTypes, varTypes, inputTypes, nestedTypeName, syntheticUnions)

		if len(nestedFields) > 0 {
			if existing, ok := syntheticTypes[nestedTypeName]; ok {
				for k, v := range nestedFields {
					if _, exists := existing.Fields[k]; !exists {
						existing.Fields[k] = v
					}
				}
			} else {
				syntheticTypes[nestedTypeName] = &inferredType{
					Name:      nestedTypeName,
					Fields:    nestedFields,
					FieldArgs: make(map[string]map[string]string),
				}
			}
		}

		if isList {
			fields[node.Name] = "[" + nestedTypeName + "]"
		} else {
			fields[node.Name] = nestedTypeName
		}
	}

	return fields
}

// inferFieldArgTypes infers argument types for a field's arguments.
func inferFieldArgTypes(args []*ast.Argument, varTypes map[string]string, inputTypes map[string]*inferredType) map[string]string {
	result := make(map[string]string)
	for _, arg := range args {
		if arg.Value != nil && arg.Value.Kind == ast.Variable {
			if t, ok := varTypes[arg.Value.Raw]; ok {
				result[arg.Name] = t
				continue
			}
		}
		if arg.Value != nil && arg.Value.Kind == ast.ObjectValue {
			inputTypeName := upperFirst(arg.Name) + "Input"
			inferInputTypeFromASTObject(arg.Value, inputTypeName, inputTypes)
			result[arg.Name] = inputTypeName
			continue
		}
		if arg.Value != nil {
			result[arg.Name] = inferTypeFromASTValue(arg.Value)
			continue
		}
		result[arg.Name] = "String"
	}
	return result
}

// storeFieldArgs stores field argument definitions on a synthetic type, creating the type if needed.
func storeFieldArgs(syntheticTypes map[string]*inferredType, typeName string, fieldName string, args map[string]string) {
	st, ok := syntheticTypes[typeName]
	if !ok {
		st = &inferredType{
			Name:      typeName,
			Fields:    make(map[string]string),
			FieldArgs: make(map[string]map[string]string),
		}
		syntheticTypes[typeName] = st
	}
	if st.FieldArgs == nil {
		st.FieldArgs = make(map[string]map[string]string)
	}
	if existing, ok := st.FieldArgs[fieldName]; ok {
		// Merge: prefer more specific types
		for k, v := range args {
			if existingType, exists := existing[k]; !exists {
				existing[k] = v
			} else if isMoreSpecificType(v, existingType) {
				existing[k] = v
			}
		}
	} else {
		st.FieldArgs[fieldName] = args
	}
}

// extractNamedType unwraps list/non-null wrappers from an AST type to get the base named type.
// E.g., [Foo!]! -> "Foo".
func extractNamedType(t *ast.Type) string {
	if t == nil {
		return ""
	}
	if t.Elem != nil {
		return extractNamedType(t.Elem)
	}
	return t.NamedType
}

// inferInputFieldsRecursive walks a JSON object and builds input type field definitions,
// creating nested input types for nested objects.
func inferInputFieldsRecursive(
	obj map[string]interface{},
	parentTypeName string,
	inputTypes map[string]*inferredType,
) map[string]string {
	fields := make(map[string]string)

	for key, val := range obj {
		switch v := val.(type) {
		case map[string]interface{}:
			nestedTypeName := parentTypeName + "_" + upperFirst(key)
			nestedFields := inferInputFieldsRecursive(v, nestedTypeName, inputTypes)
			inputTypes[nestedTypeName] = &inferredType{
				Name:   nestedTypeName,
				Fields: nestedFields,
			}
			fields[key] = nestedTypeName
		case []interface{}:
			if len(v) > 0 {
				if obj, ok := v[0].(map[string]interface{}); ok {
					elemTypeName := parentTypeName + "_" + upperFirst(key)
					elemFields := inferInputFieldsRecursive(obj, elemTypeName, inputTypes)
					inputTypes[elemTypeName] = &inferredType{
						Name:   elemTypeName,
						Fields: elemFields,
					}
					fields[key] = "[" + elemTypeName + "]"
				} else {
					fields[key] = "[" + inferTypeFromValue(v[0]) + "]"
				}
			} else {
				fields[key] = "[String]"
			}
		default:
			fields[key] = inferTypeFromValue(val)
		}
	}

	return fields
}

// inferInputTypes examines variable definitions and their runtime values to build
// input type definitions for non-scalar variable types.
func inferInputTypes(
	parsed *parsedQuery,
	variables map[string]interface{},
	inputTypes map[string]*inferredType,
) {
	for _, vd := range parsed.varDefs {
		baseType := extractNamedType(vd.Type)
		if baseType == "" || builtinScalars[baseType] {
			continue
		}

		val, ok := variables[vd.Variable]
		if !ok || val == nil {
			continue
		}

		switch v := val.(type) {
		case map[string]interface{}:
			fields := inferInputFieldsRecursive(v, baseType, inputTypes)
			if existing, ok := inputTypes[baseType]; ok {
				// Merge fields: first-wins per field
				for k, ft := range fields {
					if _, exists := existing.Fields[k]; !exists {
						existing.Fields[k] = ft
					}
				}
			} else {
				inputTypes[baseType] = &inferredType{
					Name:   baseType,
					Fields: fields,
				}
			}
		case []interface{}:
			if len(v) > 0 {
				if obj, ok := v[0].(map[string]interface{}); ok {
					// The base type is the element type name
					fields := inferInputFieldsRecursive(obj, baseType, inputTypes)
					if existing, ok := inputTypes[baseType]; ok {
						for k, ft := range fields {
							if _, exists := existing.Fields[k]; !exists {
								existing.Fields[k] = ft
							}
						}
					} else {
						inputTypes[baseType] = &inferredType{
							Name:   baseType,
							Fields: fields,
						}
					}
				}
			}
		}
	}
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

// inferTypeFromASTValue infers a GraphQL type from an AST value kind.
func inferTypeFromASTValue(v *ast.Value) string {
	if v == nil {
		return "String"
	}
	switch v.Kind {
	case ast.IntValue:
		return "Int"
	case ast.FloatValue:
		return "Float"
	case ast.BooleanValue:
		return "Boolean"
	case ast.StringValue, ast.BlockValue:
		return "String"
	case ast.ListValue:
		if len(v.Children) > 0 {
			elemType := inferTypeFromASTValue(v.Children[0].Value)
			return "[" + elemType + "]"
		}
		return "[String]"
	default:
		return "String"
	}
}

// inferInputTypeFromASTObject creates an input type definition from an AST object value.
func inferInputTypeFromASTObject(value *ast.Value, typeName string, inputTypes map[string]*inferredType) {
	if value == nil || value.Kind != ast.ObjectValue {
		return
	}

	fields := make(map[string]string)
	for _, child := range value.Children {
		if child.Value != nil && child.Value.Kind == ast.ObjectValue {
			nestedTypeName := typeName + "_" + upperFirst(child.Name)
			inferInputTypeFromASTObject(child.Value, nestedTypeName, inputTypes)
			fields[child.Name] = nestedTypeName
		} else {
			fields[child.Name] = inferTypeFromASTValue(child.Value)
		}
	}

	if existing, ok := inputTypes[typeName]; ok {
		for k, v := range fields {
			if _, exists := existing.Fields[k]; !exists {
				existing.Fields[k] = v
			}
		}
	} else {
		inputTypes[typeName] = &inferredType{
			Name:   typeName,
			Fields: fields,
		}
	}
}

// buildArgTypes builds argument type mappings. It prefers declared variable types from the AST,
// falling back to JSON value inference for variables not declared in the query.
func buildArgTypes(parsed *parsedQuery, variables map[string]interface{}, inputTypes map[string]*inferredType) map[string]string {
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
		// Fix 3: Inline object literal — create input type
		if arg.Value != nil && arg.Value.Kind == ast.ObjectValue {
			inputTypeName := upperFirst(argName) + "Input"
			inferInputTypeFromASTObject(arg.Value, inputTypeName, inputTypes)
			args[argName] = inputTypeName
			continue
		}
		// Fix 2: Infer type from inline literal value
		if arg.Value != nil {
			args[argName] = inferTypeFromASTValue(arg.Value)
			continue
		}
		// Default fallback
		args[argName] = "String"
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
			if !isMetaField(k) {
				fields[k] = inferTypeFromValue(v)
			}
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

// detectScalarReturnType checks if a GraphQL response field is a scalar value
// and returns the corresponding SDL type name.
func detectScalarReturnType(body []byte, rootFieldName string) (string, bool) {
	if len(body) == 0 {
		return "", false
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", false
	}

	data, ok := envelope["data"]
	if !ok {
		return "", false
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return "", false
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
		} else {
			return "", false
		}
	}

	switch v := responseVal.(type) {
	case string:
		return "String", true
	case bool:
		return "Boolean", true
	case float64:
		if v == math.Trunc(v) {
			return "Int", true
		}
		return "Float", true
	default:
		return "", false
	}
}

// mergeArrayElements parses a GraphQL response and merges all array elements
// for the given root field into a single map for comprehensive type inference.
func mergeArrayElements(body []byte, rootFieldName string) map[string]interface{} {
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

	responseVal, ok := dataMap[rootFieldName]
	if !ok {
		return nil
	}

	arr, ok := responseVal.([]interface{})
	if !ok {
		return nil
	}

	merged := make(map[string]interface{})
	for _, elem := range arr {
		if obj, ok := elem.(map[string]interface{}); ok {
			for k, v := range obj {
				if _, exists := merged[k]; !exists {
					merged[k] = v
				}
			}
		}
	}

	return merged
}

// mergeArrayElementsRaw merges all object elements of a raw JSON array into a single
// map, collecting the union of all fields. Used for sub-field array union inference.
func mergeArrayElementsRaw(arr []interface{}) map[string]interface{} {
	merged := make(map[string]interface{})
	for _, elem := range arr {
		if obj, ok := elem.(map[string]interface{}); ok {
			for k, v := range obj {
				if _, exists := merged[k]; !exists {
					merged[k] = v
				}
			}
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

// isMoreSpecificType returns true if newType is more specific than existingType.
// Used during merge to prefer typed args over String defaults.
func isMoreSpecificType(newType, existingType string) bool {
	if existingType == "String" && newType != "String" && newType != "" {
		return true
	}
	// Prefer non-null over nullable of the same base type
	if strings.HasSuffix(newType, "!") && !strings.HasSuffix(existingType, "!") &&
		strings.TrimSuffix(newType, "!") == existingType {
		return true
	}
	return false
}

// isScalarType returns true if the type string represents a built-in GraphQL scalar.
func isScalarType(t string) bool {
	base := strings.TrimSuffix(t, "!")
	return builtinScalars[base]
}

// scalarFieldNames returns the set of field names whose types are scalars.
func scalarFieldNames(st *inferredType) map[string]bool {
	names := make(map[string]bool)
	for fieldName, fieldType := range st.Fields {
		if isScalarType(fieldType) {
			names[fieldName] = true
		}
	}
	return names
}

// jaccardSimilarity computes |A∩B| / |A∪B| for two string sets.
func jaccardSimilarity(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	intersection := 0
	for k := range a {
		if b[k] {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

// unifyStructuralFieldTypes detects structurally similar synthetic types and
// propagates more-specific scalar field types across them. This fixes the case
// where null responses cause all fields to default to String, even when other
// operations returning the same structure have real data with correct types.
func unifyStructuralFieldTypes(syntheticTypes map[string]*inferredType) {
	// Step 1: Collect scalar field name sets for each type (skip types with < 3 scalar fields)
	type typeInfo struct {
		name        string
		scalarNames map[string]bool
	}
	var candidates []typeInfo
	for name, st := range syntheticTypes {
		sn := scalarFieldNames(st)
		if len(sn) >= 3 {
			candidates = append(candidates, typeInfo{name: name, scalarNames: sn})
		}
	}

	if len(candidates) < 2 {
		return
	}

	// Sort for deterministic grouping
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].name < candidates[j].name
	})

	// Step 2: Union-find to group structurally similar types
	parent := make([]int, len(candidates))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	union := func(x, y int) {
		px, py := find(x), find(y)
		if px != py {
			parent[px] = py
		}
	}

	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			// Count shared scalar fields
			shared := 0
			for k := range candidates[i].scalarNames {
				if candidates[j].scalarNames[k] {
					shared++
				}
			}
			if shared >= 3 && jaccardSimilarity(candidates[i].scalarNames, candidates[j].scalarNames) >= 0.5 {
				union(i, j)
			}
		}
	}

	// Step 3: Collect groups
	groups := make(map[int][]int)
	for i := range candidates {
		root := find(i)
		groups[root] = append(groups[root], i)
	}

	// Step 4: Within each group, propagate the most specific type for each scalar field
	for _, members := range groups {
		if len(members) < 2 {
			continue
		}

		// Find the best type for each field across all group members
		bestType := make(map[string]string)
		for _, idx := range members {
			st := syntheticTypes[candidates[idx].name]
			for fieldName, fieldType := range st.Fields {
				if !isScalarType(fieldType) {
					continue
				}
				if existing, ok := bestType[fieldName]; !ok {
					bestType[fieldName] = fieldType
				} else if isMoreSpecificType(fieldType, existing) {
					bestType[fieldName] = fieldType
				}
			}
		}

		// Apply best types back to all group members (only upgrade, never downgrade)
		for _, idx := range members {
			st := syntheticTypes[candidates[idx].name]
			for fieldName, best := range bestType {
				if current, ok := st.Fields[fieldName]; ok && isScalarType(current) {
					if isMoreSpecificType(best, current) {
						st.Fields[fieldName] = best
					}
				}
			}
		}
	}
}

// collectCustomScalars finds type names referenced in fields/args that are not builtins,
// not synthetic types, not synthetic input types, and not unions. These are custom scalars
// (e.g., Upload) that need explicit scalar declarations.
func collectCustomScalars(
	grouped map[string][]inferredOperation,
	syntheticTypes map[string]*inferredType,
	syntheticInputTypes map[string]*inferredType,
	syntheticUnions map[string][]string,
) []string {
	known := make(map[string]bool)
	for name := range syntheticTypes {
		known[name] = true
	}
	for name := range syntheticInputTypes {
		known[name] = true
	}
	for name := range syntheticUnions {
		known[name] = true
	}

	candidates := make(map[string]bool)

	// Check operation args
	for _, groupOps := range grouped {
		for _, op := range groupOps {
			for _, argType := range op.Args {
				checkCustomScalar(argType, known, candidates)
			}
		}
	}
	// Check synthetic type fields and field args
	for _, st := range syntheticTypes {
		for _, fieldType := range st.Fields {
			checkCustomScalar(fieldType, known, candidates)
		}
		for _, args := range st.FieldArgs {
			for _, argType := range args {
				checkCustomScalar(argType, known, candidates)
			}
		}
	}

	var scalars []string
	for s := range candidates {
		scalars = append(scalars, s)
	}
	return scalars
}

// checkCustomScalar unwraps a type string and adds any non-builtin, non-known base type
// to the candidates set.
func checkCustomScalar(typeStr string, known map[string]bool, candidates map[string]bool) {
	base := typeStr
	base = strings.TrimSuffix(base, "!")
	base = strings.TrimPrefix(base, "[")
	base = strings.TrimSuffix(base, "]")
	base = strings.TrimSuffix(base, "!")
	if base == "" || builtinScalars[base] || known[base] {
		return
	}
	candidates[base] = true
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
