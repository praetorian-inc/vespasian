package graphql

import (
	"os"
	"testing"
)

func TestParser_ParseIntrospection(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/graphql/introspection-response.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	parser := NewParser()
	endpoints, err := parser.ParseIntrospection(data)
	if err != nil {
		t.Fatalf("ParseIntrospection() error = %v", err)
	}

	if len(endpoints) == 0 {
		t.Error("ParseIntrospection() returned no endpoints")
	}

	// Check for expected query
	foundUser := false
	foundUsers := false
	for _, ep := range endpoints {
		if ep.Type == "query" && ep.Name == "user" {
			foundUser = true
		}
		if ep.Type == "query" && ep.Name == "users" {
			foundUsers = true
		}
	}

	if !foundUser {
		t.Error("ParseIntrospection() missing expected query 'user'")
	}

	if !foundUsers {
		t.Error("ParseIntrospection() missing expected query 'users'")
	}
}

func TestParser_ExtractMutations(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/graphql/introspection-response.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	parser := NewParser()
	endpoints, err := parser.ParseIntrospection(data)
	if err != nil {
		t.Fatalf("ParseIntrospection() error = %v", err)
	}

	// Check for mutations
	foundCreate := false
	foundUpdate := false
	for _, ep := range endpoints {
		if ep.Type == "mutation" && ep.Name == "createUser" {
			foundCreate = true
		}
		if ep.Type == "mutation" && ep.Name == "updateUser" {
			foundUpdate = true
		}
	}

	if !foundCreate {
		t.Error("ParseIntrospection() missing expected mutation 'createUser'")
	}

	if !foundUpdate {
		t.Error("ParseIntrospection() missing expected mutation 'updateUser'")
	}
}

func TestParser_ExtractArguments(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/graphql/introspection-response.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	parser := NewParser()
	endpoints, err := parser.ParseIntrospection(data)
	if err != nil {
		t.Fatalf("ParseIntrospection() error = %v", err)
	}

	// Find user query and check for id argument
	var userQuery *APIEndpoint
	for i := range endpoints {
		if endpoints[i].Type == "query" && endpoints[i].Name == "user" {
			userQuery = &endpoints[i]
			break
		}
	}

	if userQuery == nil {
		t.Fatal("user query not found")
	}

	if len(userQuery.Fields) == 0 {
		t.Error("user query has no fields")
	}

	if len(userQuery.Fields[0].Args) == 0 {
		t.Error("user query has no arguments")
	}

	// Check for id argument
	hasIdArg := false
	for _, arg := range userQuery.Fields[0].Args {
		if arg.Name == "id" {
			hasIdArg = true
			break
		}
	}

	if !hasIdArg {
		t.Error("user query missing id argument")
	}
}
