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
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

func strPtr(s string) *string { return &s }

func TestGenerator_APIType(t *testing.T) {
	g := &Generator{}
	if got := g.APIType(); got != "graphql" {
		t.Errorf("APIType() = %q, want %q", got, "graphql")
	}
}

func TestGenerator_DefaultExtension(t *testing.T) {
	g := &Generator{}
	if got := g.DefaultExtension(); got != ".graphql" {
		t.Errorf("DefaultExtension() = %q, want %q", got, ".graphql")
	}
}

func TestGenerator_EmptyEndpoints(t *testing.T) {
	g := &Generator{}
	_, err := g.Generate(nil)
	if err == nil {
		t.Fatal("expected error for empty endpoints")
	}
	if !strings.Contains(err.Error(), "no endpoints") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGenerator_Phase1_IntrospectionSDL(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{URL: "http://example.com/graphql"},
			APIType:         "graphql",
			GraphQLSchema: &classify.GraphQLIntrospection{
				IntrospectionEnabled: true,
				Types: []classify.GraphQLType{
					{
						Name: "Query",
						Kind: "OBJECT",
						Fields: []classify.GraphQLField{
							{Name: "user", Type: classify.GraphQLTypeRef{Name: strPtr("User"), Kind: "OBJECT"}},
							{Name: "users", Type: classify.GraphQLTypeRef{
								Kind:   "LIST",
								OfType: &classify.GraphQLTypeRef{Name: strPtr("User"), Kind: "OBJECT"},
							}},
						},
					},
					{
						Name: "Mutation",
						Kind: "OBJECT",
						Fields: []classify.GraphQLField{
							{Name: "createUser", Type: classify.GraphQLTypeRef{Name: strPtr("User"), Kind: "OBJECT"}},
						},
					},
					{
						Name: "User",
						Kind: "OBJECT",
						Fields: []classify.GraphQLField{
							{Name: "id", Type: classify.GraphQLTypeRef{Name: strPtr("ID"), Kind: "SCALAR"}},
							{Name: "name", Type: classify.GraphQLTypeRef{Name: strPtr("String"), Kind: "SCALAR"}},
						},
					},
					{
						Name: "CreateUserInput",
						Kind: "INPUT_OBJECT",
						Fields: []classify.GraphQLField{
							{Name: "name", Type: classify.GraphQLTypeRef{Name: strPtr("String"), Kind: "SCALAR"}},
							{Name: "email", Type: classify.GraphQLTypeRef{Name: strPtr("String"), Kind: "SCALAR"}},
						},
					},
				},
			},
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)

	// Verify schema block
	if !strings.Contains(sdl, "schema {") {
		t.Error("missing schema block")
	}
	if !strings.Contains(sdl, "query: Query") {
		t.Error("missing query root in schema block")
	}
	if !strings.Contains(sdl, "mutation: Mutation") {
		t.Error("missing mutation root in schema block")
	}

	// Verify type definitions
	if !strings.Contains(sdl, "type Query {") {
		t.Error("missing type Query")
	}
	if !strings.Contains(sdl, "type Mutation {") {
		t.Error("missing type Mutation")
	}
	if !strings.Contains(sdl, "type User {") {
		t.Error("missing type User")
	}
	if !strings.Contains(sdl, "input CreateUserInput {") {
		t.Error("missing input CreateUserInput")
	}

	// Verify fields
	if !strings.Contains(sdl, "users: [User]") {
		t.Error("missing LIST type rendering for users field")
	}
}

func TestGenerator_Phase1_SkipsBuiltinTypes(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "graphql",
			GraphQLSchema: &classify.GraphQLIntrospection{
				IntrospectionEnabled: true,
				Types: []classify.GraphQLType{
					{Name: "Query", Kind: "OBJECT", Fields: []classify.GraphQLField{
						{Name: "hello", Type: classify.GraphQLTypeRef{Name: strPtr("String"), Kind: "SCALAR"}},
					}},
					{Name: "__Type", Kind: "OBJECT"},
					{Name: "__Schema", Kind: "OBJECT"},
					{Name: "String", Kind: "SCALAR"},
					{Name: "Int", Kind: "SCALAR"},
					{Name: "Boolean", Kind: "SCALAR"},
					{Name: "Float", Kind: "SCALAR"},
					{Name: "ID", Kind: "SCALAR"},
				},
			},
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	for _, builtin := range []string{"__Type", "__Schema", "scalar String", "scalar Int", "scalar Boolean", "scalar Float", "scalar ID"} {
		if strings.Contains(sdl, builtin) {
			t.Errorf("output should not contain built-in type %q", builtin)
		}
	}
}

func TestGenerator_Phase1_HandlesWrappingTypes(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "graphql",
			GraphQLSchema: &classify.GraphQLIntrospection{
				IntrospectionEnabled: true,
				Types: []classify.GraphQLType{
					{
						Name: "Query",
						Kind: "OBJECT",
						Fields: []classify.GraphQLField{
							// NON_NULL wrapping a named type: String!
							{Name: "required", Type: classify.GraphQLTypeRef{
								Kind:   "NON_NULL",
								OfType: &classify.GraphQLTypeRef{Name: strPtr("String"), Kind: "SCALAR"},
							}},
							// LIST wrapping a named type: [User]
							{Name: "list", Type: classify.GraphQLTypeRef{
								Kind:   "LIST",
								OfType: &classify.GraphQLTypeRef{Name: strPtr("User"), Kind: "OBJECT"},
							}},
							// NON_NULL wrapping a LIST: [User]!
							{Name: "requiredList", Type: classify.GraphQLTypeRef{
								Kind: "NON_NULL",
								OfType: &classify.GraphQLTypeRef{
									Kind:   "LIST",
									OfType: &classify.GraphQLTypeRef{Name: strPtr("User"), Kind: "OBJECT"},
								},
							}},
						},
					},
				},
			},
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "required: String!") {
		t.Errorf("expected NON_NULL rendering 'String!', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "list: [User]") {
		t.Errorf("expected LIST rendering '[User]', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "requiredList: [User]!") {
		t.Errorf("expected NON_NULL(LIST) rendering '[User]!', got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_InferFromTraffic(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query GetUser { user { id name } }","variables":{"id":"123"}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"user":{"id":"abc","name":"Alice"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "# Inferred from observed traffic") {
		t.Error("missing inference header comment")
	}
	if !strings.Contains(sdl, "type Query {") {
		t.Error("missing type Query")
	}
	// Should use root field name "user" not operation name "GetUser"
	if !strings.Contains(sdl, "user") {
		t.Error("missing root field name 'user'")
	}
	if strings.Contains(sdl, "GetUser") {
		t.Error("should not use operation name 'GetUser' as field name")
	}
	if !strings.Contains(sdl, "id: String") {
		t.Error("missing inferred field 'id: String'")
	}
	if !strings.Contains(sdl, "name: String") {
		t.Error("missing inferred field 'name: String'")
	}
}

func TestGenerator_Phase2_MutationDetection(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"mutation CreateUser { createUser { id } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"createUser":{"id":"1"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "type Mutation {") {
		t.Errorf("expected 'type Mutation', got:\n%s", sdl)
	}
	// Should use root field name "createUser"
	if !strings.Contains(sdl, "createUser") {
		t.Error("missing root field name 'createUser'")
	}
}

func TestGenerator_Phase2_VariableTypeInference(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query Search($term: String, $limit: Int, $active: Boolean, $score: Float) { search(term: $term, limit: $limit, active: $active, score: $score) { id } }","variables":{"term":"hello","limit":10,"active":true,"score":3.14}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"search":{"id":"1"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "term: String") {
		t.Errorf("expected 'term: String' in args, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "limit: Int") {
		t.Errorf("expected 'limit: Int' in args, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "active: Boolean") {
		t.Errorf("expected 'active: Boolean' in args, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "score: Float") {
		t.Errorf("expected 'score: Float' in args, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_ArrayResponse(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query GetPastes { pastes { id title content public } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"pastes":[{"id":"1","title":"First","content":"Hello","public":true},{"id":"2","title":"Second","content":"World","public":false}]}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	// Should use list return type
	if !strings.Contains(sdl, "[PastesResponse]") {
		t.Errorf("expected list return type '[PastesResponse]', got:\n%s", sdl)
	}
	// Should have the response type with fields from the array elements
	if !strings.Contains(sdl, "type PastesResponse {") {
		t.Errorf("expected 'type PastesResponse', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "id: String") {
		t.Errorf("expected 'id: String' in PastesResponse, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "title: String") {
		t.Errorf("expected 'title: String' in PastesResponse, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "public: Boolean") {
		t.Errorf("expected 'public: Boolean' in PastesResponse, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_TypedVariableDefinitions(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"mutation CreatePaste($title: String!, $content: String!, $public: Boolean) { createPaste(title: $title, content: $content, public: $public) { id } }","variables":{"title":"Test","content":"Body","public":true}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"createPaste":{"id":"42"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	// Should preserve non-null modifier from variable definition
	if !strings.Contains(sdl, "title: String!") {
		t.Errorf("expected 'title: String!' (non-null from variable def), got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "content: String!") {
		t.Errorf("expected 'content: String!' (non-null from variable def), got:\n%s", sdl)
	}
	// Boolean without ! should remain nullable
	if !strings.Contains(sdl, "public: Boolean") {
		t.Errorf("expected 'public: Boolean' (nullable), got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_NestedSelectionSet(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query GetUser { user { id name email } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"user":{"id":"1","name":"Alice","email":"alice@example.com","internalField":"secret"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	// Should include fields from the selection set
	if !strings.Contains(sdl, "id: String") {
		t.Errorf("expected 'id: String', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "name: String") {
		t.Errorf("expected 'name: String', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "email: String") {
		t.Errorf("expected 'email: String', got:\n%s", sdl)
	}
	// Selection set is authoritative — fields not in it should be excluded
	if strings.Contains(sdl, "internalField") {
		t.Error("should not include 'internalField' which is not in the selection set")
	}
}

func TestGenerator_Phase1_FallsToPhase2(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query Hello { hello { message } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"hello":{"message":"world"}}}`),
				},
			},
			APIType: "graphql",
			GraphQLSchema: &classify.GraphQLIntrospection{
				IntrospectionEnabled: false,
			},
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	// Should have fallen through to phase 2
	if !strings.Contains(sdl, "# Inferred from observed traffic") {
		t.Error("expected phase 2 inference header")
	}
	// Should use root field name "hello"
	if !strings.Contains(sdl, "hello") {
		t.Error("expected root field name 'hello'")
	}
}

func TestGenerator_DeterministicOutput(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "graphql",
			GraphQLSchema: &classify.GraphQLIntrospection{
				IntrospectionEnabled: true,
				Types: []classify.GraphQLType{
					{Name: "Zebra", Kind: "OBJECT", Fields: []classify.GraphQLField{
						{Name: "stripes", Type: classify.GraphQLTypeRef{Name: strPtr("Int"), Kind: "SCALAR"}},
					}},
					{Name: "Apple", Kind: "OBJECT", Fields: []classify.GraphQLField{
						{Name: "color", Type: classify.GraphQLTypeRef{Name: strPtr("String"), Kind: "SCALAR"}},
					}},
					{Name: "Query", Kind: "OBJECT", Fields: []classify.GraphQLField{
						{Name: "zebra", Type: classify.GraphQLTypeRef{Name: strPtr("Zebra"), Kind: "OBJECT"}},
						{Name: "apple", Type: classify.GraphQLTypeRef{Name: strPtr("Apple"), Kind: "OBJECT"}},
					}},
				},
			},
		},
	}

	out1, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("first Generate() error: %v", err)
	}

	out2, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("second Generate() error: %v", err)
	}

	if string(out1) != string(out2) {
		t.Errorf("output is not deterministic:\nfirst:\n%s\nsecond:\n%s", out1, out2)
	}

	// Verify alphabetical ordering: Apple before Query before Zebra
	sdl := string(out1)
	appleIdx := strings.Index(sdl, "type Apple")
	queryIdx := strings.Index(sdl, "type Query")
	zebraIdx := strings.Index(sdl, "type Zebra")
	if appleIdx > queryIdx || queryIdx > zebraIdx {
		t.Error("types should be sorted alphabetically")
	}
}

func TestGenerator_Phase2_FragmentSpreadResolution(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query FooQuery { ...Foo_root } fragment Foo_root on Query { user { id name } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"user":{"id":"1","name":"Alice"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	// Should resolve through the fragment spread to find "user" as root field
	if !strings.Contains(sdl, "user") {
		t.Errorf("expected root field 'user' resolved from fragment spread, got:\n%s", sdl)
	}
	// Should NOT fall back to anonymous naming
	if strings.Contains(sdl, "anonymous") {
		t.Errorf("should not have anonymous naming when fragment resolves to a field, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_OperationNameFallback(t *testing.T) {
	g := &Generator{}
	// A query where the fragment spread cannot resolve to a field (fragment has no fields, only nested spreads)
	// but the operation has a name — should use operation name as fallback
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query BaggagePreferencesQuery { ...BaggageRoot } fragment BaggageRoot on Query { preferences { baggage } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"preferences":{"baggage":"carry-on"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	// Should resolve the fragment to find "preferences" as root field
	if !strings.Contains(sdl, "preferences") {
		t.Errorf("expected root field 'preferences', got:\n%s", sdl)
	}
	if strings.Contains(sdl, "anonymous") {
		t.Errorf("should not have anonymous naming, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_DedupPreservesDistinctOperations(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query StoredPassengers { viewer { passengers { id name } } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"viewer":{"passengers":[{"id":"1","name":"Alice"}]}}}`),
				},
			},
			APIType: "graphql",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query FareLocksTabQuery { viewer { fareLocks { id status } } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"viewer":{"fareLocks":[{"id":"2","status":"active"}]}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	// Both operations should be merged into a single "viewer" field
	if !strings.Contains(sdl, "viewer") {
		t.Errorf("expected 'viewer' field, got:\n%s", sdl)
	}
	// Should NOT have disambiguated fields — they should be merged
	if strings.Contains(sdl, "viewer_FareLocksTabQuery") {
		t.Errorf("should not have disambiguated 'viewer_FareLocksTabQuery' — operations should be merged, got:\n%s", sdl)
	}
	// The merged ViewerResponse should contain fields from both operations
	if !strings.Contains(sdl, "passengers") {
		t.Errorf("expected 'passengers' field from first operation in merged type, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "fareLocks") {
		t.Errorf("expected 'fareLocks' field from second operation in merged type, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_GETRequestWithQueryParams(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "http://example.com/graphql?query=query%20GetStatus%20%7B%20status%20%7B%20healthy%20version%20%7D%20%7D",
				Body:   nil,
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"status":{"healthy":true,"version":"1.0"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "status") {
		t.Errorf("expected root field 'status' from GET request, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "healthy: Boolean") {
		t.Errorf("expected 'healthy: Boolean' field, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_MultipartFormData(t *testing.T) {
	g := &Generator{}
	boundary := "----WebKitFormBoundary7MA4YWxkTrZu0gW"
	multipartBody := "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
		"Content-Disposition: form-data; name=\"operations\"\r\n\r\n" +
		`{"query":"mutation UploadFile($file: Upload!) { uploadFile(file: $file) { id url } }","variables":{"file":null}}` + "\r\n" +
		"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
		"Content-Disposition: form-data; name=\"map\"\r\n\r\n" +
		`{"0":["variables.file"]}` + "\r\n" +
		"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
		"Content-Disposition: form-data; name=\"0\"; filename=\"test.txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"file content\r\n" +
		"------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/graphql",
				Headers: map[string]string{"Content-Type": "multipart/form-data; boundary=" + boundary},
				Body:    []byte(multipartBody),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"uploadFile":{"id":"42","url":"https://example.com/file.txt"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "type Mutation {") {
		t.Errorf("expected 'type Mutation', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "uploadFile") {
		t.Errorf("expected root field 'uploadFile' from multipart request, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "file: Upload!") {
		t.Errorf("expected 'file: Upload!' argument, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_NestedObjectType(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query GetUser { user { id profile { bio avatar } } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"user":{"id":"1","profile":{"bio":"hi","avatar":"pic.png"}}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "profile: User_ProfileResponse") {
		t.Errorf("expected 'profile: User_ProfileResponse', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "type User_ProfileResponse {") {
		t.Errorf("expected 'type User_ProfileResponse', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "bio: String") {
		t.Errorf("expected 'bio: String' in nested type, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "avatar: String") {
		t.Errorf("expected 'avatar: String' in nested type, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "id: String") {
		t.Errorf("expected 'id: String' in root type, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_MultiLevelNesting(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query GetViewer { viewer { locale { language { code } currency { code } } } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"viewer":{"locale":{"language":{"code":"en"},"currency":{"code":"USD"}}}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "locale: Viewer_LocaleResponse") {
		t.Errorf("expected 'locale: Viewer_LocaleResponse', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "type Viewer_LocaleResponse {") {
		t.Errorf("expected 'type Viewer_LocaleResponse', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "language: Viewer_Locale_LanguageResponse") {
		t.Errorf("expected 'language: Viewer_Locale_LanguageResponse', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "currency: Viewer_Locale_CurrencyResponse") {
		t.Errorf("expected 'currency: Viewer_Locale_CurrencyResponse', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "type Viewer_Locale_LanguageResponse {") {
		t.Errorf("expected 'type Viewer_Locale_LanguageResponse', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "type Viewer_Locale_CurrencyResponse {") {
		t.Errorf("expected 'type Viewer_Locale_CurrencyResponse', got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_InlineFragmentMerging(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query GetUser { user { id ... on Admin { role } ... on Member { level } } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"user":{"id":"1","role":"admin","level":"senior"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "role: String") {
		t.Errorf("expected 'role: String' from inline fragment, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "level: String") {
		t.Errorf("expected 'level: String' from inline fragment, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "id: String") {
		t.Errorf("expected 'id: String', got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_NestedArray(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query GetUser { user { id posts { id title } } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"user":{"id":"1","posts":[{"id":"10","title":"Hello"},{"id":"11","title":"World"}]}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "posts: [User_PostsResponse]") {
		t.Errorf("expected 'posts: [User_PostsResponse]', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "type User_PostsResponse {") {
		t.Errorf("expected 'type User_PostsResponse', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "title: String") {
		t.Errorf("expected 'title: String' in nested array type, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_NamedFragmentWithNesting(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query GetUser { user { ...UserFields } } fragment UserFields on User { id profile { bio } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"user":{"id":"1","profile":{"bio":"hello"}}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "profile: User_ProfileResponse") {
		t.Errorf("expected 'profile: User_ProfileResponse' from fragment, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "type User_ProfileResponse {") {
		t.Errorf("expected 'type User_ProfileResponse', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "bio: String") {
		t.Errorf("expected 'bio: String' in nested type from fragment, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_TypenameFiltered(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query GetUser { user { __typename id name } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"user":{"__typename":"User","id":"1","name":"Alice"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if strings.Contains(sdl, "__typename") {
		t.Errorf("__typename should be filtered from output, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "id: String") {
		t.Errorf("expected 'id: String', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "name: String") {
		t.Errorf("expected 'name: String', got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_MergedFieldsWithNesting(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query StoredPassengers { viewer { passengers { id name } } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"viewer":{"passengers":[{"id":"1","name":"Alice"}]}}}`),
				},
			},
			APIType: "graphql",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query FareLocksTabQuery { viewer { fareLocks { id status } } }","variables":{}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"viewer":{"fareLocks":[{"id":"2","status":"active"}]}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)

	// Should have a single "viewer" field (merged, not disambiguated)
	if strings.Contains(sdl, "viewer_FareLocksTabQuery") {
		t.Errorf("should not have disambiguated field — operations should be merged, got:\n%s", sdl)
	}

	// Merged ViewerResponse should contain fields from both operations
	if !strings.Contains(sdl, "type ViewerResponse {") {
		t.Errorf("expected 'type ViewerResponse', got:\n%s", sdl)
	}

	// Both nested types should use Viewer_ prefix (field-name based)
	if !strings.Contains(sdl, "passengers: [Viewer_PassengersResponse]") {
		t.Errorf("expected 'passengers: [Viewer_PassengersResponse]', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "type Viewer_PassengersResponse {") {
		t.Errorf("expected 'type Viewer_PassengersResponse', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "fareLocks: [Viewer_FareLocksResponse]") {
		t.Errorf("expected 'fareLocks: [Viewer_FareLocksResponse]', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "type Viewer_FareLocksResponse {") {
		t.Errorf("expected 'type Viewer_FareLocksResponse', got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_MergedArgs(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query SearchA($term: String!) { search(term: $term) { id } }","variables":{"term":"hello"}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"search":{"id":"1"}}}`),
				},
			},
			APIType: "graphql",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"query SearchB($term: String!, $limit: Int) { search(term: $term, limit: $limit) { id title } }","variables":{"term":"world","limit":10}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"search":{"id":"2","title":"Result"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)

	// Should have a single "search" field with merged args from both operations
	if !strings.Contains(sdl, "term: String!") {
		t.Errorf("expected 'term: String!' from first operation, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "limit: Int") {
		t.Errorf("expected 'limit: Int' from second operation, got:\n%s", sdl)
	}
	// Should NOT have disambiguated fields
	if strings.Contains(sdl, "search_SearchB") {
		t.Errorf("should not have disambiguated field — operations should be merged, got:\n%s", sdl)
	}
	// Merged response should contain fields from both operations
	if !strings.Contains(sdl, "id: String") {
		t.Errorf("expected 'id: String' in merged response, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "title: String") {
		t.Errorf("expected 'title: String' from second operation in merged response, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_InputTypeScalarFields(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"mutation CreateEvent($input: NewEventsInput!) { createEvent(input: $input) { id } }","variables":{"input":{"title":"Conference","count":5,"active":true,"rating":4.5}}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"createEvent":{"id":"1"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "input NewEventsInput {") {
		t.Errorf("expected 'input NewEventsInput', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "title: String") {
		t.Errorf("expected 'title: String' in input type, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "count: Int") {
		t.Errorf("expected 'count: Int' in input type, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "active: Boolean") {
		t.Errorf("expected 'active: Boolean' in input type, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "rating: Float") {
		t.Errorf("expected 'rating: Float' in input type, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_InputTypeNestedObjects(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"mutation UpdateIdentity($input: UpdateIdentityInput!) { updateIdentity(input: $input) { id } }","variables":{"input":{"name":"Alice","address":{"street":"123 Main St","city":"Springfield"}}}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"updateIdentity":{"id":"1"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "input UpdateIdentityInput {") {
		t.Errorf("expected 'input UpdateIdentityInput', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "name: String") {
		t.Errorf("expected 'name: String' in input type, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "address: UpdateIdentityInput_Address") {
		t.Errorf("expected 'address: UpdateIdentityInput_Address' in input type, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "input UpdateIdentityInput_Address {") {
		t.Errorf("expected nested 'input UpdateIdentityInput_Address', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "street: String") {
		t.Errorf("expected 'street: String' in nested input type, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "city: String") {
		t.Errorf("expected 'city: String' in nested input type, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_InputTypeArrayOfObjects(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"mutation AddItems($items: [ItemInput!]!) { addItems(items: $items) { count } }","variables":{"items":[{"name":"Widget","qty":3},{"name":"Gadget","qty":1}]}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"addItems":{"count":2}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "input ItemInput {") {
		t.Errorf("expected 'input ItemInput', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "name: String") {
		t.Errorf("expected 'name: String' in input type, got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "qty: Int") {
		t.Errorf("expected 'qty: Int' in input type, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_InputTypeMergeAcrossOperations(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"mutation CreateA($input: SharedInput!) { createA(input: $input) { id } }","variables":{"input":{"name":"Alice"}}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"createA":{"id":"1"}}}`),
				},
			},
			APIType: "graphql",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"mutation CreateB($input: SharedInput!) { createB(input: $input) { id } }","variables":{"input":{"name":"Bob","email":"bob@example.com"}}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"createB":{"id":"2"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	if !strings.Contains(sdl, "input SharedInput {") {
		t.Errorf("expected 'input SharedInput', got:\n%s", sdl)
	}
	if !strings.Contains(sdl, "name: String") {
		t.Errorf("expected 'name: String' in merged input type, got:\n%s", sdl)
	}
	// Second op adds "email" field — should be merged in
	if !strings.Contains(sdl, "email: String") {
		t.Errorf("expected 'email: String' from second op merged into SharedInput, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_InputTypeCustomScalarSkipped(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"mutation UploadFile($file: Upload!) { uploadFile(file: $file) { id } }","variables":{"file":null}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"uploadFile":{"id":"42"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	// Upload variable is null — should NOT generate an input type for it
	if strings.Contains(sdl, "input Upload {") {
		t.Errorf("should not generate input type for custom scalar Upload, got:\n%s", sdl)
	}
}

func TestGenerator_Phase2_InputTypeNullVariableSkipped(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:  "http://example.com/graphql",
				Body: []byte(`{"query":"mutation Update($input: UpdateInput!) { update(input: $input) { id } }","variables":{"input":null}}`),
				Response: crawl.ObservedResponse{
					Body: []byte(`{"data":{"update":{"id":"1"}}}`),
				},
			},
			APIType: "graphql",
		},
	}

	out, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sdl := string(out)
	// Null variable value — should NOT generate an input type
	if strings.Contains(sdl, "input UpdateInput {") {
		t.Errorf("should not generate input type for null variable, got:\n%s", sdl)
	}
}
