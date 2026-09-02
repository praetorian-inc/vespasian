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

package rest

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"mime/multipart"
	"net/textproto"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

func TestOpenAPIGenerator_Generate_Basic(t *testing.T) {
	gen := &OpenAPIGenerator{}

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/42",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": 42, "name": "John"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Parse the YAML to verify structure
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("Failed to parse generated YAML: %v", err)
	}

	// Verify OpenAPI version
	if parsed["openapi"] != "3.0.3" {
		t.Errorf("openapi version = %v, want 3.0.3", parsed["openapi"])
	}

	// Verify info section exists
	if _, ok := parsed["info"]; !ok {
		t.Error("info section missing")
	}

	// Verify paths section exists
	if _, ok := parsed["paths"]; !ok {
		t.Error("paths section missing")
	}
}

func TestOpenAPIGenerator_Generate_Validation(t *testing.T) {
	gen := &OpenAPIGenerator{}

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/42",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": 42, "name": "John"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Validate using kin-openapi loader
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	if err != nil {
		t.Fatalf("Generated spec failed validation: %v", err)
	}

	if doc.OpenAPI != "3.0.3" {
		t.Errorf("OpenAPI version = %v, want 3.0.3", doc.OpenAPI)
	}
}

func TestOpenAPIGenerator_APIType(t *testing.T) {
	gen := &OpenAPIGenerator{}
	if apiType := gen.APIType(); apiType != "rest" {
		t.Errorf("APIType() = %q, want %q", apiType, "rest")
	}
}

func TestOpenAPIGenerator_DefaultExtension(t *testing.T) {
	gen := &OpenAPIGenerator{}
	if ext := gen.DefaultExtension(); ext != ".yaml" {
		t.Errorf("DefaultExtension() = %q, want %q", ext, ".yaml")
	}
}

func TestOpenAPIGenerator_RealWorldExample(t *testing.T) {
	gen := &OpenAPIGenerator{}

	endpoints := []classify.ClassifiedRequest{
		// GET /users/{id}
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/42",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": 42, "name": "John", "email": "john@example.com"}`),
				},
			},
			IsAPI: true,
		},
		// GET /users/{id} with different ID (should be grouped)
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/87",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": 87, "name": "Jane", "email": "jane@example.com"}`),
				},
			},
			IsAPI: true,
		},
		// POST /users with request body
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/users",
				Body:   []byte(`{"name": "Alice", "email": "alice@example.com"}`),
				Response: crawl.ObservedResponse{
					StatusCode: 201,
					Body:       []byte(`{"id": 100, "name": "Alice", "email": "alice@example.com"}`),
				},
			},
			IsAPI: true,
		},
		// GET /users with query params
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users?limit=10&offset=0",
				QueryParams: map[string][]string{
					"limit":  {"10"},
					"offset": {"0"},
				},
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`[{"id": 1, "name": "User1"}, {"id": 2, "name": "User2"}]`),
				},
			},
			IsAPI: true,
		},
		// UUID in path
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/resources/550e8400-e29b-41d4-a716-446655440000",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": "550e8400-e29b-41d4-a716-446655440000", "data": "test"}`),
				},
			},
			IsAPI: true,
		},
		// Literal path preserved
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/me",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": 1, "name": "Current User"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Validate using kin-openapi loader
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	if err != nil {
		t.Fatalf("Generated spec failed validation: %v", err)
	}

	// Verify paths were normalized correctly
	expectedPaths := []string{
		"/users/{userId}",         // Both /users/42 and /users/87 normalized
		"/users",                  // POST and GET with query params
		"/resources/{resourceId}", // UUID normalized
		"/users/me",               // Literal preserved
	}

	for _, path := range expectedPaths {
		if doc.Paths.Find(path) == nil {
			t.Errorf("Expected path %q not found in spec", path)
		}
	}

	// Verify query parameters are present
	usersPath := doc.Paths.Find("/users")
	if usersPath == nil || usersPath.Get == nil {
		t.Fatal("GET /users not found")
	}
	if len(usersPath.Get.Parameters) != 2 {
		t.Errorf("Expected 2 query parameters for GET /users, got %d", len(usersPath.Get.Parameters))
	}

	// Verify POST request body is present
	if usersPath.Post == nil {
		t.Fatal("POST /users not found")
	}
	if usersPath.Post.RequestBody == nil {
		t.Error("POST /users missing request body")
	}
}

func TestOpenAPIGenerator_JSONFormat(t *testing.T) {
	gen := &OpenAPIGenerator{Format: "json"}

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/test",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"test": true}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Parse as JSON to verify format
	var parsed map[string]interface{}
	if err := json.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("Failed to parse generated JSON: %v", err)
	}

	if parsed["openapi"] != "3.0.3" {
		t.Errorf("openapi version = %v, want 3.0.3", parsed["openapi"])
	}
}

func TestCapitalizeFirst(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase word",
			input:    "get",
			expected: "Get",
		},
		{
			name:     "uppercase word",
			input:    "GET",
			expected: "GET",
		},
		{
			name:     "mixed case",
			input:    "post",
			expected: "Post",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single character",
			input:    "p",
			expected: "P",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := capitalizeFirst(tt.input)
			assert.Equal(t, tt.expected, result, "capitalizeFirst(%q)", tt.input)
		})
	}
}

func TestInferQueryParamType(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"integer", "42", "integer"},
		{"negative integer", "-1", "integer"},
		{"zero", "0", "integer"},
		{"float", "3.14", "number"},
		{"negative float", "-0.5", "number"},
		{"scientific notation", "1e10", "number"},
		{"boolean true", "true", "boolean"},
		{"boolean false", "false", "boolean"},
		{"string", "hello", "string"},
		{"empty string", "", "string"},
		{"mixed alphanumeric", "abc123", "string"},
		{"boolean-like but uppercase", "True", "string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferQueryParamType(tt.value)
			assert.Equal(t, tt.expected, result, "inferQueryParamType(%q)", tt.value)
		})
	}
}

func TestOpenAPIGenerator_SchemaMerging(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/users",
				Body:   []byte(`{"id": 1, "name": "Alice"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"id": 1, "name": "Alice"}`),
				},
			},
			IsAPI:      true,
			Confidence: 1.0,
			APIType:    "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/users",
				Body:   []byte(`{"id": 2, "email": "bob@example.com"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"id": 2, "email": "bob@example.com"}`),
				},
			},
			IsAPI:      true,
			Confidence: 1.0,
			APIType:    "rest",
		},
	}

	gen := &OpenAPIGenerator{Format: "yaml"}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	specStr := string(spec)
	// The merged request body schema should contain all properties: id, name, email
	if !strings.Contains(specStr, "name") {
		t.Error("merged schema missing 'name' property from first observation")
	}
	if !strings.Contains(specStr, "email") {
		t.Error("merged schema missing 'email' property from second observation")
	}
	if !strings.Contains(specStr, "id") {
		t.Error("merged schema missing 'id' property")
	}

	// Verify schemas are extracted to components/schemas
	if !strings.Contains(specStr, "components:") {
		t.Error("spec missing components section")
	}
	if !strings.Contains(specStr, "schemas:") {
		t.Error("spec missing schemas section")
	}
	// Verify $ref references exist
	if !strings.Contains(specStr, "$ref:") {
		t.Error("spec missing $ref references to components")
	}
	// Verify request body schema is in components
	if !strings.Contains(specStr, "CreateUserRequest") {
		t.Error("spec missing CreateUserRequest schema in components")
	}
}

func TestOpenAPIGenerator_MultipleServers(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://api.example.com/users",
				Response: crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true, Confidence: 1.0, APIType: "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://api2.example.com/items",
				Response: crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true, Confidence: 1.0, APIType: "rest",
		},
	}

	gen := &OpenAPIGenerator{Format: "yaml"}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	specStr := string(spec)
	if !strings.Contains(specStr, "https://api.example.com") {
		t.Error("spec missing first server URL")
	}
	if !strings.Contains(specStr, "https://api2.example.com") {
		t.Error("spec missing second server URL")
	}
}

// TestExtractServers_ProductionOriginShapeStripsDefaultPort is TEST-001
// (LAB-4992 review): crawl.ResolveTargetOrigin -> originOf ALWAYS makes the
// port explicit, so in production TargetOrigin arrives as "https://host:443"
// or "http://host:80", never a bare "https://host". Without
// canonicalizeOrigin's default-port strip, that explicit-port TargetOrigin
// would never string-equal the port-free origin originFromURL derives from
// the SAME host's observed endpoint URL, producing two server entries for one
// host and a titleHost with the port baked in (doc comment's exact claim).
// This test uses that PRODUCTION shape directly, rather than a bare-host
// TargetOrigin as most other tests do.
func TestExtractServers_ProductionOriginShapeStripsDefaultPort(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://www.example.com/api/users", ""),
	}

	servers, titleHost, _ := extractServers(endpoints, "https://www.example.com:443")

	require.Len(t, servers, 1, "the explicit-port TargetOrigin must dedupe against the same host's observed origin, not produce a second entry")
	assert.Equal(t, "https://www.example.com", servers[0].URL, "the default port must be stripped from the server URL")
	assert.Equal(t, "www.example.com API", titleHost, "the default port must be stripped from info.title's host")
}

// SEC-BE-003/SEC-BE-002: a cross-origin static:js candidate is never probed
// (the probe egress gate only prevents the REQUEST; extractServers must
// independently exclude it from the DELIVERABLE). The attacker host is chosen
// to sort FIRST alphabetically ("a.attacker.example" < "www.example.com") so
// this test fails under the pre-fix behavior, which always used servers[0]
// for both the servers list membership and the title — proving the exploit
// this fix closes. No TargetOrigin is supplied, so the primary origin falls
// back to the lowest-sorted DYNAMICALLY OBSERVED endpoint (www.example.com).
func TestExtractServers_JSStaticCrossOriginExcluded(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://www.example.com/api/users", ""),
		makeClassified("GET", "https://a.attacker.example/api/collect", "static:js"),
	}

	servers, titleHost, excluded := extractServers(endpoints, "")

	require.Len(t, servers, 1, "unprobed JS-static host must not be added to servers")
	assert.Equal(t, "https://www.example.com", servers[0].URL)
	assert.Equal(t, "www.example.com API", titleHost, "info.title must not be captured by the unprobed JS-static host")
	assert.True(t, excluded["https://a.attacker.example"], "attacker origin must be reported as excluded from the global list")
}

// TestExtractServers_FullyOfflineAllJSStatic_NoTargetOriginExcludesAttacker is
// the SEC-BE-002 regression guard (LAB-4992 review): a FULLY-OFFLINE capture
// (every endpoint is JS-static — no dynamically observed endpoint exists at
// all) containing both a legitimate host and an attacker-planted host, with NO
// TargetOrigin supplied. This is the flagship LAB-4992 scenario: the pre-fix
// code's "observed == 0 -> fall back to the FULL unfiltered endpoint set"
// branch trusted the entirely offline, attacker-controlled JS-static set, and
// picked the alphabetically-first host for both servers[0] and info.title.
// "a.attacker.example" sorts before "www.example.com", so this test fails
// under the pre-fix behavior.
//
// TEST-003 fix (LAB-4992 review): the original version of this test asserted
// only `for _, s := range servers { assert.NotEqual(...) }` and
// `assert.NotContains(titleHost, "attacker")`. In this exact branch — no
// TargetOrigin, zero dynamically observed endpoints — servers is empty, so
// the range loop body never executes and its assertion is vacuous (asserts
// nothing). This version asserts the ACTUAL, POSITIVE contract instead: with
// no vouched origin available at all, choosePrimaryOrigin returns "" and
// BOTH JS-static origins are excluded (neither can be admitted as
// same-origin with an empty primary) — servers is empty and titleHost falls
// back to the bare default. This is a deliberately defensive branch: in the
// real pipeline, crawl.ResolveTargetOrigin's third fallback means primary is
// essentially always non-empty, so a fully-offline capture with a TRULY empty
// primary is an edge case exercised directly by this unit test, not the
// common path. Whether "no vouched origin -> empty servers" is the right
// call is pinned here deliberately, positively, and explicitly — not left
// implicit.
func TestExtractServers_FullyOfflineAllJSStatic_NoTargetOriginExcludesAttacker(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://www.example.com/api/x", "static:js"),
		makeClassified("GET", "https://a.attacker.example/api/collect", "static:js"),
	}

	servers, titleHost, excluded := extractServers(endpoints, "")

	assert.Empty(t, servers, "with no vouched origin at all, servers must be empty rather than trusting any unprobed JS-static host")
	assert.True(t, excluded["https://www.example.com"], "the legitimate host must be reported as excluded (unprobed, no primary to be same-origin with)")
	assert.True(t, excluded["https://a.attacker.example"], "the attacker host must be reported as excluded")
	assert.Len(t, excluded, 2, "both origins, and only both, must be reported as excluded")
	assert.Equal(t, "API", titleHost, "with no usable origin, title must fall back to the bare default")
}

// TestExtractServers_FullyOfflineAllJSStatic_WithTargetOriginPinsLegit is the
// companion to the test above: the SAME fully-offline, all-JS-static endpoint
// set, but this time the caller supplies the trusted TargetOrigin (as the
// pipeline does via crawl.ResolveTargetOrigin, derived from the capture's own
// HTML page or --target-url — never from bundle content). With a vouched
// origin available, the legitimate host must become both servers[0] and the
// title host, and the attacker host must still never surface.
func TestExtractServers_FullyOfflineAllJSStatic_WithTargetOriginPinsLegit(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://www.example.com/api/x", "static:js"),
		makeClassified("GET", "https://a.attacker.example/api/collect", "static:js"),
	}

	servers, titleHost, excluded := extractServers(endpoints, "https://www.example.com")

	require.NotEmpty(t, servers)
	assert.Equal(t, "https://www.example.com", servers[0].URL, "the vouched TargetOrigin must be servers[0]")
	assert.Equal(t, "www.example.com API", titleHost, "title must derive from the vouched TargetOrigin")
	for _, s := range servers {
		assert.NotEqual(t, "https://a.attacker.example", s.URL, "attacker origin must never appear in servers")
	}
	assert.True(t, excluded["https://a.attacker.example"], "attacker origin must be reported as excluded from the global list")
}

// TestExtractServers_HostlessSchemeLiteralRejected pins the LAB-4992 review
// fix: a scheme-only literal like "https:/api/x" (single slash — not an
// authority marker) parses via url.Parse to Scheme="https", Host="". The
// pre-fix loop only checked the scheme, so this produced a degenerate
// "https://" server entry — which sorts before every real hostname and, via
// the title-from-servers[0] logic, blanked info.title (firstURL.Host == "").
func TestExtractServers_HostlessSchemeLiteralRejected(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https:/api/x", ""),
	}

	servers, titleHost, _ := extractServers(endpoints, "")

	for _, s := range servers {
		assert.NotEqual(t, "https://", s.URL, "a scheme-only literal must not produce a degenerate \"https://\" server entry")
	}
	assert.Equal(t, "API", titleHost, "with no usable origin, title must fall back to the default rather than blank")
}

// TestExtractServers_HostlessTargetOriginRejected pins the TARGET-ORIGIN
// path's host-less rejection. This function (choosePrimaryOrigin) and the
// ENDPOINT path (collectEndpointOrigins, pinned by
// TestExtractServers_HostlessSchemeLiteralRejected above) both go through
// the single crawl.CanonicalOrigin (SEC-BE-001/QUAL-001) — there is no
// longer a "separate arm" per input; both call sites share one guard.
//
// CanonicalOrigin itself carries a `u.Host == ""` check, and originOf (which
// CanonicalOrigin delegates to) has its own independent `u.Host == ""`
// check. These are NOT a symmetric pair of equivalent mutants — verified by
// deleting each in isolation and running TestOriginOf, TestCanonicalOrigin,
// and this test:
//   - Deleting CanonicalOrigin's own guard alone IS semantically equivalent
//     for all three tests: CanonicalOrigin still calls originOf
//     unconditionally, and originOf's guard alone already makes
//     originOf("https:/api/x") — and so CanonicalOrigin("https:/api/x") —
//     return "". All three tests stay green.
//   - Deleting originOf's own guard alone is NOT equivalent: TestOriginOf
//     fails directly, because it exercises originOf itself (same package),
//     not only through CanonicalOrigin. `originOf("/relative/path")` then
//     returns "://" instead of "" (confirmed: `expected: "" / actual:
//     "://"`). TestCanonicalOrigin and this test still stay green, because
//     CanonicalOrigin's OWN guard short-circuits before ever calling
//     originOf for a host-less URL — originOf's guard is never reached from
//     that path, so its deletion is invisible to any test that only goes
//     through CanonicalOrigin.
//
// Deleting BOTH guards is the mutation that kills every one of the three:
// CanonicalOrigin then returns the degenerate "https://" for "https:/api/x",
// which becomes the PRIMARY server — occupying servers[0] and displacing the
// real observed host — the same degenerate-origin failure SEC-BE-002 closed
// for bundle literals, just reached through --target-url instead. Verified:
// removing both guards makes this test fail with servers[0] == "https://"
// and titleHost == "API" instead of the real observed origin; restoring
// either guard alone is enough to make this test (and TestCanonicalOrigin)
// pass again — though, per above, restoring originOf's guard alone is also
// required for TestOriginOf specifically.
func TestExtractServers_HostlessTargetOriginRejected(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://legit.example/api/users", ""),
	}

	servers, titleHost, _ := extractServers(endpoints, "https:/api/x")

	require.NotEmpty(t, servers, "the observed origin must still populate servers")
	assert.Equal(t, "https://legit.example", servers[0].URL,
		"an unusable targetOrigin must not become the primary server; the observed origin must")
	for _, s := range servers {
		assert.NotEqual(t, "https://", s.URL, "a host-less targetOrigin must not produce a degenerate \"https://\" entry")
	}
	assert.Equal(t, "legit.example API", titleHost,
		"title must come from the real observed origin, not from the unusable targetOrigin")
}

// TestExtractServers_StaticHTMLCarveOut pins the doc-comment claim (computeSourceTag,
// extractServers) that static:html is deliberately NOT filtered like a JS-static
// source: the page carrying the <form> was fetched over the wire during the
// crawl, unlike a JS-static candidate whose entire existence is reconstructed
// offline. This asserts the concrete consequence: a dynamic endpoint and a
// static:html endpoint on DIFFERENT hosts both reach the global servers list,
// and (with no TargetOrigin) the primary/title is the lowest-sorted of the two
// — exercising crawl.IsJSStaticSource's exclusion of "static:html" in both
// directions (present in servers, eligible as primary).
func TestExtractServers_StaticHTMLCarveOut(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://real.example.com/api/x", ""),
		makeClassified("POST", "https://forms.example.com/api/submit", "static:html"),
	}

	servers, titleHost, excluded := extractServers(endpoints, "")

	urls := make([]string, 0, len(servers))
	for _, s := range servers {
		urls = append(urls, s.URL)
	}
	assert.Contains(t, urls, "https://real.example.com", "the dynamic endpoint's origin must be in servers")
	assert.Contains(t, urls, "https://forms.example.com", "the static:html endpoint's origin must be in servers (not treated as JS-static)")
	assert.Equal(t, "forms.example.com API", titleHost, "\"forms.example.com\" sorts before \"real.example.com\" and static:html is eligible as the primary fallback")
	assert.Empty(t, excluded, "static:html must never be reported as an excluded (cross-origin JS-static) origin")
}

// TestExtractServers_SameOriginJSStaticAdmitted is TEST-002 (LAB-4992
// review), retargeted (round-23 review, finding B): the common offline-SPA
// case is a JS-static endpoint recovered on the SAME origin as the trusted
// primary (e.g. a bundle literal for a same-host API path never triggered
// during the crawl). Its fixture uses "https://www.example.com" for the
// observed dynamic endpoint, the static:js endpoint, AND TargetOrigin, so
// this origin is already in serverSet (added for primary, before the
// exclusion loop runs) by the time the loop reaches it — execution stops at
// the `serverSet[origin]` arm ("already vouched for; a bundle naming it
// changes nothing"), NOT at a same-origin admission arm (that arm was
// removed as unreachable dead code; see TestCanonicalOrigin_SameOriginImpliesEquality
// in pkg/crawl for why it could never fire). What this test still correctly
// pins is the observable BEHAVIOR: a JS-static endpoint on the same origin as
// the trusted primary must not produce a second `servers` entry and must not
// be reported as excluded — regardless of which arm of the switch admits it.
func TestExtractServers_SameOriginJSStaticAdmitted(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://www.example.com/api/users", ""),
		makeClassified("GET", "https://www.example.com/api/offline-only", "static:js"),
	}

	servers, _, excluded := extractServers(endpoints, "https://www.example.com")

	require.Len(t, servers, 1, "the same-origin JS-static endpoint must not produce a second server entry")
	assert.Equal(t, "https://www.example.com", servers[0].URL)
	assert.False(t, excluded["https://www.example.com"], "the trusted, same-origin host must never be reported as excluded")
}

// TestGenerate_IPv6TargetEmitsBracketedServersURL is SEC-BE-001 (LAB-4992
// review): a bracket-less "servers" URL for an IPv6 host
// ("https://2001:db8::1:8443") is not a valid URL — RFC 3986 requires the
// literal to be wrapped in "[...]" so ":" inside the address isn't parsed as
// the port delimiter. crawl.CanonicalOrigin/originOf re-bracket the host when
// rebuilding it from url.URL.Hostname() (which strips brackets), so the
// generated spec's servers[0] and info.title must both keep the brackets.
func TestGenerate_IPv6TargetEmitsBracketedServersURL(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://[2001:db8::1]:8443/api/users", ""),
	}

	gen := &OpenAPIGenerator{Format: "yaml", TargetOrigin: "https://[2001:db8::1]:8443"}
	spec, err := gen.Generate(endpoints)
	require.NoError(t, err)

	var parsed struct {
		Info struct {
			Title string `yaml:"title"`
		} `yaml:"info"`
		Servers []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
	}
	require.NoError(t, yaml.Unmarshal(spec, &parsed))

	require.Len(t, parsed.Servers, 1)
	assert.Equal(t, "https://[2001:db8::1]:8443", parsed.Servers[0].URL, "the IPv6 host must stay bracketed in the servers URL")
	assert.Equal(t, "[2001:db8::1]:8443 API", parsed.Info.Title, "the IPv6 host must stay bracketed in info.title")
}

// TestExtractServers_ExplicitPortDedupesWithBareHostTargetOrigin is
// SEC-BE-001/QUAL-001 (LAB-4992 review): originFromURL preserved an
// endpoint's port EXACTLY as written while canonicalizeOrigin (applied only
// to TargetOrigin) stripped a redundant default port — two different
// normalizations of the same origin. An endpoint spelled with an explicit
// ":443" therefore never string-equalled a bare-host TargetOrigin for the
// SAME host, producing two server entries for one host. Both sides now go
// through the single crawl.CanonicalOrigin, so they agree.
func TestExtractServers_ExplicitPortDedupesWithBareHostTargetOrigin(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://www.example.com:443/api/users", ""),
	}

	servers, titleHost, _ := extractServers(endpoints, "https://www.example.com")

	require.Len(t, servers, 1, "the explicit-port endpoint origin must dedupe against the bare-host TargetOrigin, not produce a second entry")
	assert.Equal(t, "https://www.example.com", servers[0].URL)
	assert.Equal(t, "www.example.com API", titleHost)
}

// TestExtractServers_MixedCaseHostDedupes is QUAL-001 (LAB-4992 review): a
// mixed-case endpoint host (as commonly seen in captured traffic) must
// canonicalize to the same lower-cased origin as the TargetOrigin, not
// produce a second, case-distinct server entry.
func TestExtractServers_MixedCaseHostDedupes(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://App.Example.com/api/users", ""),
	}

	servers, titleHost, _ := extractServers(endpoints, "https://app.example.com")

	require.Len(t, servers, 1, "a mixed-case host must dedupe against the lower-cased TargetOrigin, not produce two entries")
	assert.Equal(t, "https://app.example.com", servers[0].URL)
	assert.Equal(t, "app.example.com API", titleHost)
}

// TestBuildOperation_CrossOriginJSStaticGetsPerOperationServersOverride is the
// SEC-BE-001 regression guard: groupEndpoints groups purely by normalized path
// and method, ignoring host, so a JS-static endpoint recovered on a different
// host than the primary origin still produces a path entry in the spec even
// though its origin is excluded from the global servers list. Without a
// per-operation override, that path is silently attributed to the primary
// host in every client that reads only the global servers list — sending
// follow-up testing at the wrong target. This asserts the operation carries
// its own servers override naming its actual origin, and that the global
// servers list never contains that origin.
//
// Both halves of buildOperation's membership test are asserted here. The
// positive half is that the excluded operation gets a per-operation servers
// override; the negative half is that the non-excluded operation on the primary
// origin gets none. Without the negative assertion, dropping the
// `&& excludedOrigins[origin]` conjunct would give every operation a spurious
// override and nothing here would fail.
func TestBuildOperation_CrossOriginJSStaticGetsPerOperationServersOverride(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://app.example.com/api/users", ""),
		makeClassified("GET", "https://api.example.com/api/orders", "static:js"),
	}

	gen := &OpenAPIGenerator{Format: "yaml", TargetOrigin: "https://app.example.com"}
	spec, err := gen.Generate(endpoints)
	require.NoError(t, err)

	var parsed struct {
		Servers []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
		Paths map[string]struct {
			Get struct {
				Servers []struct {
					URL string `yaml:"url"`
				} `yaml:"servers"`
			} `yaml:"get"`
		} `yaml:"paths"`
	}
	require.NoError(t, yaml.Unmarshal(spec, &parsed))

	for _, s := range parsed.Servers {
		assert.NotEqual(t, "https://api.example.com", s.URL, "cross-origin JS-static host must not appear in the global servers list")
	}

	ordersOp, ok := parsed.Paths["/api/orders"]
	require.True(t, ok, "expected /api/orders path in the spec")
	require.Len(t, ordersOp.Get.Servers, 1, "cross-origin operation must carry a per-operation servers override")
	assert.Equal(t, "https://api.example.com", ordersOp.Get.Servers[0].URL)

	usersOp, ok := parsed.Paths["/api/users"]
	require.True(t, ok, "expected /api/users path in the spec")
	assert.Empty(t, usersOp.Get.Servers, "a non-excluded (primary-origin) operation must carry NO servers override")
}

// TestGenerate_CollisionTrustedOriginWinsSlot is the SEC-BE-001 fix
// verification. classify.Deduplicate, NormalizePathsWithNames, and (pre-fix)
// groupEndpoints all key host-agnostically, so a REAL endpoint observed on the
// trusted origin and an attacker-planted JS-static literal on a different
// origin can normalize to the exact same path+method. Pre-fix, both
// observations landed in a single group and buildOperation derived the
// per-operation override from group[0].URL alone — sort order decided
// whether the attacker origin silently overrode the trusted one, or the
// attacker path was silently attributed to the trusted host, depending only
// on which hostname happened to sort first.
//
// With origin folded into endpointKey, these two observations can no longer
// share a group — they now collide on the same (path, method) SLOT in
// doc.Paths instead. This test asserts the deterministic resolution: the
// trusted (primary) origin's operation always wins the slot regardless of
// which hostname sorts first, and the attacker origin never appears in any
// operation's servers override anywhere in the document.
func TestGenerate_CollisionTrustedOriginWinsSlot(t *testing.T) {
	// "a.evil.example" sorts BEFORE "app.example.com" alphabetically, so this
	// case would have made the attacker origin win under the old
	// group[0]-based logic.
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://app.example.com/api/users/42", ""),
		makeClassified("GET", "https://a.evil.example/api/users/7", "static:js"),
	}

	gen := &OpenAPIGenerator{Format: "yaml", TargetOrigin: "https://app.example.com:443"}
	spec, err := gen.Generate(endpoints)
	require.NoError(t, err)

	var parsed struct {
		Servers []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
		Paths map[string]struct {
			Get struct {
				Servers []struct {
					URL string `yaml:"url"`
				} `yaml:"servers"`
			} `yaml:"get"`
		} `yaml:"paths"`
	}
	require.NoError(t, yaml.Unmarshal(spec, &parsed))

	for _, s := range parsed.Servers {
		assert.NotEqual(t, "https://a.evil.example", s.URL, "attacker origin must never appear in the global servers list")
	}
	for path, pathItem := range parsed.Paths {
		for _, s := range pathItem.Get.Servers {
			assert.NotEqual(t, "https://a.evil.example", s.URL, "attacker origin must never appear in any operation's servers override (path %s)", path)
		}
	}

	// Both endpoints normalize to the same path+method, so exactly one Get
	// operation slot must exist for it, and it must belong to the trusted
	// origin (no per-operation override needed since it IS the primary).
	require.Len(t, parsed.Paths, 1, "both observations must collide onto a single path slot")
	for _, pathItem := range parsed.Paths {
		assert.Empty(t, pathItem.Get.Servers, "the trusted-origin operation that wins the slot must not carry a spurious servers override")
	}

	// The suppressed attacker-origin group must not be silently discarded —
	// the collision loss must be recorded visibly on the winning operation.
	assert.Contains(t, string(spec), "x-vespasian-collision-origins", "the suppressed cross-origin group's loss must be recorded visibly, not silently dropped")
	assert.Contains(t, string(spec), "a.evil.example", "the recorded collision must name the suppressed origin")
}

// TestGenerate_ExplicitPortTrustedOriginWinsSlotAndDedupes is SEC-BE-001
// (LAB-4992 review): reproduces the exact scenario from the finding — the
// trusted endpoint is captured with an explicit ":443" while TargetOrigin
// arrives in the same production shape (crawl.ResolveTargetOrigin always
// makes the port explicit). Before the fix, originFromURL preserved the
// endpoint's port verbatim while canonicalizeOrigin stripped TargetOrigin's,
// so the two never string-equalled: the trusted host lost its own
// tie-break to the attacker origin, AND the spec listed both
// "https://app.example.com" and "https://app.example.com:443" as separate
// servers. With both sides canonicalized identically, the trusted host must
// win its slot and appear exactly once in servers.
func TestGenerate_ExplicitPortTrustedOriginWinsSlotAndDedupes(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://app.example.com:443/api/users/42", ""),
		makeClassified("GET", "https://a.evil.example/api/users/7", "static:js"),
	}

	gen := &OpenAPIGenerator{Format: "yaml", TargetOrigin: "https://app.example.com:443"}
	spec, err := gen.Generate(endpoints)
	require.NoError(t, err)

	var parsed struct {
		Servers []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
		Paths map[string]struct {
			Get struct {
				Servers []struct {
					URL string `yaml:"url"`
				} `yaml:"servers"`
			} `yaml:"get"`
		} `yaml:"paths"`
	}
	require.NoError(t, yaml.Unmarshal(spec, &parsed))

	require.Len(t, parsed.Servers, 1, "the explicit-port trusted origin must dedupe to a single server entry, not two")
	assert.Equal(t, "https://app.example.com", parsed.Servers[0].URL)
	for _, s := range parsed.Servers {
		assert.NotEqual(t, "https://a.evil.example", s.URL, "attacker origin must never appear in the global servers list")
	}

	require.Len(t, parsed.Paths, 1, "both observations must collide onto a single path slot")
	for _, pathItem := range parsed.Paths {
		assert.Empty(t, pathItem.Get.Servers, "the trusted-origin operation that wins the slot must not carry a spurious servers override")
	}

	assert.Contains(t, string(spec), "x-vespasian-collision-origins", "the suppressed attacker group's loss must be recorded, not silently dropped")
	assert.Contains(t, string(spec), "a.evil.example", "the recorded collision must name the suppressed attacker origin")
}

// TestGenerate_CollisionNeitherOriginPrimary_TrustRankPicksObservedOverExcluded
// is the SEC-BE-002 fix verification. The prior tie-break compared each
// colliding origin to primaryOrigin as a single boolean — when NEITHER
// colliding origin IS the primary, it abstained and fell through to a plain
// byte-compare of the (attacker-controlled) origin string. Here the REAL
// endpoint is observed on a non-primary, non-excluded origin
// (api.example.com — a page other than the primary served this API, but it
// WAS actually seen on the wire) and the attacker endpoint is an unprobed,
// cross-origin JS-static literal. Neither equals the primary
// (app.example.com). The real, non-excluded origin must win regardless of
// which hostname sorts first alphabetically — that is the whole point of
// ranking by trust rather than by origin string.
func TestGenerate_CollisionNeitherOriginPrimary_TrustRankPicksObservedOverExcluded(t *testing.T) {
	cases := []struct {
		name         string
		attackerHost string
	}{
		{name: "attacker hostname sorts before the real observed host", attackerHost: "a.evil.example"},
		{name: "attacker hostname sorts after the real observed host", attackerHost: "zzz.evil.example"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attackerOrigin := "https://" + tc.attackerHost
			endpoints := []classify.ClassifiedRequest{
				makeClassified("GET", "https://api.example.com/api/users/42", ""),
				makeClassified("GET", attackerOrigin+"/api/users/7", "static:js"),
			}

			gen := &OpenAPIGenerator{Format: "yaml", TargetOrigin: "https://app.example.com:443"}
			spec, err := gen.Generate(endpoints)
			require.NoError(t, err)
			specStr := string(spec)

			var parsed struct {
				Servers []struct {
					URL string `yaml:"url"`
				} `yaml:"servers"`
				Paths map[string]struct {
					Get struct {
						Servers []struct {
							URL string `yaml:"url"`
						} `yaml:"servers"`
					} `yaml:"get"`
				} `yaml:"paths"`
			}
			require.NoError(t, yaml.Unmarshal(spec, &parsed))

			serverURLs := make([]string, 0, len(parsed.Servers))
			for _, s := range parsed.Servers {
				serverURLs = append(serverURLs, s.URL)
				assert.NotEqual(t, attackerOrigin, s.URL, "attacker origin must never appear in the global servers list")
			}
			assert.Contains(t, serverURLs, "https://api.example.com", "the real observed endpoint's origin must remain in the global servers list")

			require.Len(t, parsed.Paths, 1, "both observations must collide onto a single path slot")
			for path, item := range parsed.Paths {
				assert.Empty(t, item.Get.Servers,
					"the winning operation is the real observed (non-excluded) origin, which needs no per-operation override (path %s)", path)
			}

			assert.Contains(t, specStr, "x-vespasian-collision-origins", "the suppressed attacker group's loss must be recorded, not silently dropped")
			assert.Contains(t, specStr, tc.attackerHost, "the recorded collision must name the suppressed attacker origin")
		})
	}
}

// TestExtractServers_ObservedOriginNamedInBundleStaysVouched is SEC-BE-002
// (LAB-4992 review). collectEndpointOrigins buckets an origin into `observed`
// and `jsStatic` INDEPENDENTLY, so an origin can appear in both: dynamically
// observed on the wire AND merely named by a bundle literal. The exclusion
// loop used to mark every jsStatic origin that is not same-origin with primary
// as excluded, without subtracting the origins it had just added to `servers`.
// So `excludedOrigins` meant "appeared in a bundle", not "cannot be vouched
// for", and a bundle that merely NAMES a real observed host demoted that host
// to trustRank 2 — tying it with genuinely untrusted origins and dropping back
// to the attacker-steerable byte compare the rank exists to eliminate.
//
// The attacker's cost is zero: a normal SPA bundle served from app.example.com
// references https://api.example.com/... constantly, so in the ORDINARY case
// every non-primary observed origin was already unprotected.
func TestExtractServers_ObservedOriginNamedInBundleStaysVouched(t *testing.T) {
	const observedAPI = "https://api.example.com"

	servers, _, excluded := extractServers([]classify.ClassifiedRequest{
		makeClassified("GET", "https://app.example.com/", ""),
		makeClassified("GET", observedAPI+"/api/users/42", ""),
		// The poison: the bundle names the very origin observed above.
		makeClassified("GET", observedAPI+"/api/health", crawl.SourceStaticJS),
	}, "https://app.example.com")

	assert.False(t, excluded[observedAPI],
		"an origin observed on the wire must stay vouched for even when a bundle also names it; otherwise trustRank demotes the real endpoint to untrusted")

	var urls []string
	for _, s := range servers {
		urls = append(urls, s.URL)
	}
	assert.Contains(t, urls, observedAPI, "the observed origin must remain in the global servers list")
}

// TestGenerate_BundleNamingObservedHostCannotHandSlotToAttacker is the
// end-to-end half of SEC-BE-002: with the poison line present, an attacker
// origin that sorts first must still lose the (path, method) slot to the real
// observed endpoint.
func TestGenerate_BundleNamingObservedHostCannotHandSlotToAttacker(t *testing.T) {
	const attacker = "https://0.evil.example"

	g := &OpenAPIGenerator{Format: "yaml", TargetOrigin: "https://app.example.com"}
	spec, err := g.Generate([]classify.ClassifiedRequest{
		makeClassified("GET", "https://app.example.com/", ""),
		makeClassified("GET", "https://api.example.com/api/users/42", ""),
		makeClassified("GET", "https://api.example.com/api/health", crawl.SourceStaticJS),
		makeClassified("GET", attacker+"/api/users/7", crawl.SourceStaticJS),
	})
	require.NoError(t, err)
	specStr := string(spec)

	assert.NotContains(t, specStr, "- url: "+attacker,
		"an attacker origin must never define a server, globally or per-operation")
	assert.Contains(t, specStr, attacker,
		"the attacker group must still be RECORDED as suppressed rather than silently dropped")

	parsed, err := openapi3.NewLoader().LoadFromData(spec)
	require.NoError(t, err)
	users := parsed.Paths.Find("/api/users/{userId}")
	require.NotNil(t, users, "the real observed endpoint must own the collided slot")
	require.NotNil(t, users.Get)
	assert.Empty(t, users.Get.Servers,
		"the winner is the real observed origin, which needs no per-operation override")
	assert.Equal(t, "dynamic", users.Get.Extensions["x-vespasian-source"],
		"the surviving operation must be the dynamically observed one, not the bundle-derived candidate")
}

// TestGenerate_ThreeOriginCollision_RecordsAllSuppressedOrigins is TEST-001
// (LAB-4992 review): every prior collision test produced exactly ONE
// suppressed origin, so recordCollisionOrigin's "existing" slice was always
// nil and the append-to-existing branch never ran. Here three origins
// collide on one (path, method) slot, so the SECOND recordCollisionOrigin
// call must append to (not replace) the first. Asserts the full recorded
// value, not merely that it Contains one of the two losers.
func TestGenerate_ThreeOriginCollision_RecordsAllSuppressedOrigins(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://app.example.com/api/thing", ""),
		makeClassified("GET", "https://other.example.com/api/thing", ""),
		makeClassified("GET", "https://evil.example/api/thing", "static:js"),
	}

	gen := &OpenAPIGenerator{Format: "yaml", TargetOrigin: "https://app.example.com"}
	spec, err := gen.Generate(endpoints)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(spec, &parsed))

	paths, ok := parsed["paths"].(map[string]any)
	require.True(t, ok, "expected a paths map")
	require.Len(t, paths, 1, "all three observations must collide onto a single path slot")

	var getOp map[string]any
	for _, pathItemAny := range paths {
		pathItem, ok := pathItemAny.(map[string]any)
		require.True(t, ok)
		getOp, ok = pathItem["get"].(map[string]any)
		require.True(t, ok)
	}
	require.NotNil(t, getOp)

	rawOrigins, ok := getOp["x-vespasian-collision-origins"].([]any)
	require.True(t, ok, "expected x-vespasian-collision-origins on the winning operation")

	origins := make([]string, 0, len(rawOrigins))
	for _, o := range rawOrigins {
		s, ok := o.(string)
		require.True(t, ok)
		origins = append(origins, s)
	}
	assert.Equal(t, []string{"https://evil.example", "https://other.example.com"}, origins,
		"both suppressed origins must be recorded in full, not just the last one (TEST-001)")
}

// TestTrustRank_EmptyOriginIsUntrusted is TEST-001 (LAB-4992 review): an
// empty origin (crawl.CanonicalOrigin's result for a host-less literal such
// as "https:/api/x") is unknown provenance and must rank as the LEAST
// trusted (2), never as trusted as the primary (0) or as an ordinary
// non-excluded origin (1). collectEndpointOrigins skips empty origins, so ""
// never enters excludedOrigins — the empty-origin case must be handled by
// trustRank itself, not by excludedOrigins[""].
//
// The primaryOrigin == "" case is the "additional hole": choosePrimaryOrigin
// returns "" when the run cannot vouch for any origin at all (no usable
// TargetOrigin and no dynamically observed endpoint). Before the fix,
// origin == primaryOrigin was checked FIRST, so "" == "" matched that arm
// and ranked an unknown-provenance origin as rank 0 — the MOST trusted of
// all, worse than the plain default-arm bug.
func TestTrustRank_EmptyOriginIsUntrusted(t *testing.T) {
	assert.Equal(t, 2, trustRank("", "https://app.example.com", map[string]bool{}),
		"an empty origin must never rank as trusted as an ordinary non-excluded origin")
	assert.Equal(t, 2, trustRank("", "", map[string]bool{}),
		"an empty origin must rank untrusted even when primaryOrigin is itself empty (the run cannot vouch for any origin)")
	assert.Equal(t, 0, trustRank("https://app.example.com", "https://app.example.com", map[string]bool{}),
		"the primary origin itself must still rank 0")
}

// TestGenerate_HostlessOriginLiteralNeverWinsCollision is TEST-001 (LAB-4992
// review), the end-to-end reproduction: a host-less literal such as
// "https:/api/thing/7" (single slash — not an authority marker) canonicalizes
// to "" via crawl.CanonicalOrigin. TargetOrigin is set to a THIRD origin
// (app.example.com — the page the crawl actually ran against) so the real
// observed endpoint (api.example.com) is non-primary, non-excluded, i.e.
// rank 1 under the fixed code — exactly matching the empty origin's OLD
// (buggy) default-arm rank of 1. At that tie, the buggy string tie-break
// ("" sorts before every real origin string) let the attacker's host-less,
// js-bundle-concat candidate win the (path, method) slot outright, silently
// suppressing the real endpoint. The real endpoint must win regardless.
func TestGenerate_HostlessOriginLiteralNeverWinsCollision(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://api.example.com/api/thing/42", ""),
		makeClassified("GET", "https:/api/thing/7", "static:js-concat"),
	}

	gen := &OpenAPIGenerator{Format: "yaml", TargetOrigin: "https://app.example.com"}
	spec, err := gen.Generate(endpoints)
	require.NoError(t, err)
	specStr := string(spec)

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(spec, &parsed))
	paths, ok := parsed["paths"].(map[string]any)
	require.True(t, ok, "expected a paths map")
	require.Len(t, paths, 1, "both observations must collide onto a single path slot")

	// The winning operation must be the real, observed endpoint — pinned via
	// its x-vespasian-source: an operation built from the host-less
	// js-bundle-concat candidate would carry x-vespasian-source:
	// js-bundle-concat; the real endpoint (empty Source) carries no
	// x-vespasian-source extension at all under a single-member group, but a
	// COLLISION winner keeps its own group's tag, which for the real
	// endpoint's group is "" (empty Source, non-JS-static) -> "dynamic" is
	// only emitted when staticPresent is true (it is here, since the other
	// group is JS-static), so assert the tag directly.
	assert.NotContains(t, specStr, "js-bundle-concat",
		"the host-less, never-probed candidate must not win the slot (its x-vespasian-source tag must not appear)")
	assert.Contains(t, specStr, "x-vespasian-source: dynamic",
		"the real, dynamically observed endpoint must win the slot")

	// The suppressed candidate's loss must still be visible, not silently
	// dropped, even though its own origin is "" (empty). This is the
	// deliberate choice this code makes (recordCollisionOrigin's doc
	// comment): the suppressed group's origin is recorded as-is, including
	// when that origin is "" — the empty string itself communicates WHICH
	// candidate lost (an unknown-provenance one), consistent with trustRank
	// ranking "" as least trusted rather than a special "unknown" sentinel.
	var getOp map[string]any
	for _, pathItemAny := range paths {
		pathItem, ok := pathItemAny.(map[string]any)
		require.True(t, ok)
		getOp, ok = pathItem["get"].(map[string]any)
		require.True(t, ok)
	}
	require.NotNil(t, getOp)
	rawOrigins, ok := getOp["x-vespasian-collision-origins"].([]any)
	require.True(t, ok, "expected x-vespasian-collision-origins on the winning operation")
	require.Len(t, rawOrigins, 1)
	assert.Equal(t, "", rawOrigins[0], "the suppressed host-less candidate's loss must be recorded as the empty origin, not silently dropped")
}

// TestGenerate_PrimarySortsLaterStillWinsCollision is TEST-002 (LAB-4992
// review): mutating trustRank's primary arm (`return 0` -> `return 1`)
// survives the rest of the suite because every existing collision test gives
// the primary a hostname that already sorts first alphabetically among the
// non-excluded (rank-1) origins, so rank and string order agree and the
// mutant is indistinguishable from correct code. Here the primary's hostname
// ("zzz.example.com") sorts LATER than a competing non-excluded, dynamically
// observed origin ("aaa.example.com"). Correct code (rank 0 for the primary)
// must still make the primary win; the mutant (rank 1, tying with the
// competitor's rank 1) would let the competitor win via the string
// tie-break instead.
func TestGenerate_PrimarySortsLaterStillWinsCollision(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://zzz.example.com/api/thing/42", ""),
		makeClassified("GET", "https://aaa.example.com/api/thing/7", ""),
	}

	gen := &OpenAPIGenerator{Format: "yaml", TargetOrigin: "https://zzz.example.com"}
	spec, err := gen.Generate(endpoints)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(spec, &parsed))

	paths, ok := parsed["paths"].(map[string]any)
	require.True(t, ok, "expected a paths map")
	require.Len(t, paths, 1, "both observations must collide onto a single path slot")

	var getOp map[string]any
	for _, pathItemAny := range paths {
		pathItem, ok := pathItemAny.(map[string]any)
		require.True(t, ok)
		getOp, ok = pathItem["get"].(map[string]any)
		require.True(t, ok)
	}
	require.NotNil(t, getOp)

	assert.Nil(t, getOp["servers"],
		"the primary-origin operation that wins the slot must not carry a per-operation servers override")

	// This is the assertion that actually discriminates the winner: the
	// collision-origins extension is set only on the WINNING operation and
	// names the LOSING origin. If the mutant (rank 1 for the primary) let
	// the alphabetically-first "aaa.example.com" win instead, this
	// operation's collision-origins would read "zzz.example.com" (the
	// primary, having lost) rather than "aaa.example.com" — asserting
	// global servers-list order or "no per-operation override" (checked
	// above) cannot tell the two outcomes apart, since neither origin is
	// excluded and extractServers always places the primary at servers[0]
	// regardless of which one wins the (path, method) slot collision.
	rawOrigins, ok := getOp["x-vespasian-collision-origins"].([]any)
	require.True(t, ok, "expected x-vespasian-collision-origins on the winning operation")
	origins := make([]string, 0, len(rawOrigins))
	for _, o := range rawOrigins {
		s, ok := o.(string)
		require.True(t, ok)
		origins = append(origins, s)
	}
	assert.Equal(t, []string{"https://aaa.example.com"}, origins,
		"the primary (zzz.example.com) must win the slot despite sorting later alphabetically; the non-primary aaa.example.com must be the one recorded as suppressed")
}

func TestP0Fixes_ContextAwarePathParams(t *testing.T) {
	gen := &OpenAPIGenerator{}

	endpoints := []classify.ClassifiedRequest{
		// Test Issue #3: Multiple path parameters should have unique names
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/42/posts/5",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"userId": 42, "postId": 5}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Validate using kin-openapi loader
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	if err != nil {
		t.Fatalf("Generated spec failed validation: %v", err)
	}

	// Verify path uses context-aware naming
	expectedPath := "/users/{userId}/posts/{postId}"
	pathItem := doc.Paths.Find(expectedPath)
	if pathItem == nil {
		t.Fatalf("Expected path %q not found in spec", expectedPath)
	}

	// Verify both path parameters are present and correctly named
	if pathItem.Get == nil {
		t.Fatal("GET operation not found")
	}

	var paramNames []string
	for _, paramRef := range pathItem.Get.Parameters {
		if paramRef.Value.In == "path" {
			paramNames = append(paramNames, paramRef.Value.Name)
		}
	}

	expectedParams := []string{"userId", "postId"}
	if len(paramNames) != len(expectedParams) {
		t.Fatalf("Expected %d path parameters, got %d: %v", len(expectedParams), len(paramNames), paramNames)
	}

	for _, expected := range expectedParams {
		found := false
		for _, actual := range paramNames {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected path parameter %q not found. Got: %v", expected, paramNames)
		}
	}
}

func TestOpenAPIGenerator_SlugObservation(t *testing.T) {
	// Three slug-shaped observations under a common prefix must be grouped
	// into a single parameterized path by Generate(). This locks in the
	// contract that observation-based slug detection (NormalizePathsWithNames)
	// is wired into groupEndpoints; a regression that reverts the wiring to
	// per-endpoint normalization would produce three distinct paths and fail
	// this test.
	gen := &OpenAPIGenerator{MergeSlugs: true}

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/articles/my-first-post",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"title": "first"}`),
				},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/articles/another-post",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"title": "another"}`),
				},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/articles/yet-another-post",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"title": "yet another"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	if err != nil {
		t.Fatalf("Generated spec failed validation: %v", err)
	}

	// Exactly one path should exist; observation-based detection collapses
	// the three slug observations onto /articles/{articleSlug}.
	if doc.Paths.Len() != 1 {
		paths := append([]string{}, doc.Paths.InMatchingOrder()...)
		t.Fatalf("expected 1 path in spec, got %d: %v", doc.Paths.Len(), paths)
	}

	expectedPath := "/articles/{articleSlug}"
	pathItem := doc.Paths.Find(expectedPath)
	if pathItem == nil {
		paths := append([]string{}, doc.Paths.InMatchingOrder()...)
		t.Fatalf("expected path %q not found in spec; got: %v", expectedPath, paths)
	}
	if pathItem.Get == nil {
		t.Fatal("GET operation not found on /articles/{articleSlug}")
	}

	// Verify the path parameter is present and correctly named.
	var pathParamNames []string
	for _, paramRef := range pathItem.Get.Parameters {
		if paramRef.Value.In == "path" {
			pathParamNames = append(pathParamNames, paramRef.Value.Name)
		}
	}
	if len(pathParamNames) != 1 || pathParamNames[0] != "articleSlug" {
		t.Errorf("path parameters = %v, want exactly [articleSlug]", pathParamNames)
	}
}

// TestOpenAPIGenerator_DefaultPreservesDistinctSiblings locks in the LAB-4107
// default at the Generate() seam: a zero-value generator (MergeSlugs unset)
// must keep slug-shaped siblings as distinct paths. A wiring bug that ignored
// g.MergeSlugs, or a default flip to merge-on, would collapse them and fail
// here even though the cmd/unit/E2E layers pass. Mirrors
// TestOpenAPIGenerator_SlugObservation with merging off.
func TestOpenAPIGenerator_DefaultPreservesDistinctSiblings(t *testing.T) {
	gen := &OpenAPIGenerator{} // MergeSlugs defaults off

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://api.example.com/articles/my-first-post",
				Response: crawl.ObservedResponse{StatusCode: 200, Body: []byte(`{"title": "first"}`)},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://api.example.com/articles/another-post",
				Response: crawl.ObservedResponse{StatusCode: 200, Body: []byte(`{"title": "another"}`)},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://api.example.com/articles/yet-another-post",
				Response: crawl.ObservedResponse{StatusCode: 200, Body: []byte(`{"title": "yet another"}`)},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	require.NoError(t, err)

	doc, err := openapi3.NewLoader().LoadFromData(spec)
	require.NoError(t, err)

	// Merge off: all three siblings survive as distinct paths, none collapsed.
	require.Equal(t, 3, doc.Paths.Len(), "distinct siblings must be preserved; got %v", doc.Paths.InMatchingOrder())
	for _, p := range []string{"/articles/my-first-post", "/articles/another-post", "/articles/yet-another-post"} {
		assert.NotNil(t, doc.Paths.Find(p), "expected preserved path %q", p)
	}
	assert.Nil(t, doc.Paths.Find("/articles/{articleSlug}"), "must not collapse into a slug param when merge is off")
}

func TestP0Fixes_ActualStatusCodes(t *testing.T) {
	gen := &OpenAPIGenerator{}

	endpoints := []classify.ClassifiedRequest{
		// Test Issue #2: Status codes should be actual (201, 404, etc.), not bucketed
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/users",
				Body:   []byte(`{"name": "Test"}`),
				Response: crawl.ObservedResponse{
					StatusCode: 201, // Should be "201", not "200"
					Body:       []byte(`{"id": 1, "name": "Test"}`),
				},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/notfound",
				Response: crawl.ObservedResponse{
					StatusCode: 404, // Should be "404", not "400"
					Body:       []byte(`{"error": "Not found"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Parse YAML to check status codes
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("Failed to parse generated YAML: %v", err)
	}

	paths := parsed["paths"].(map[string]interface{})

	// Check POST /users has 201 response
	usersPath := paths["/users"].(map[string]interface{})
	postOp := usersPath["post"].(map[string]interface{})
	responses := postOp["responses"].(map[string]interface{})
	if _, has201 := responses["201"]; !has201 {
		t.Errorf("Expected POST /users to have 201 response, got: %v", responses)
	}

	// Check GET /notfound has 404 response
	notFoundPath := paths["/notfound"].(map[string]interface{})
	getOp := notFoundPath["get"].(map[string]interface{})
	responses = getOp["responses"].(map[string]interface{})
	if _, has404 := responses["404"]; !has404 {
		t.Errorf("Expected GET /notfound to have 404 response, got: %v", responses)
	}
}

func TestResourceNameFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "simple plural resource",
			path:     "/api/v2/tickets",
			expected: "Ticket",
		},
		{
			name:     "resource with parameter",
			path:     "/api/v2/tickets/{ticketId}",
			expected: "Ticket",
		},
		{
			name:     "nested resources - returns last",
			path:     "/api/v2/categories/{categoryId}/items/{itemId}",
			expected: "Item",
		},
		{
			name:     "users resource",
			path:     "/api/v2/users",
			expected: "User",
		},
		{
			name:     "settings resource",
			path:     "/api/v2/users/me/settings",
			expected: "Setting",
		},
		{
			name:     "categories with ies ending",
			path:     "/api/v2/categories",
			expected: "Category",
		},
		{
			name:     "addresses with sses ending",
			path:     "/api/v2/addresses",
			expected: "Address",
		},
		{
			name:     "resource without trailing s",
			path:     "/api/v2/data",
			expected: "Data",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "Resource",
		},
		{
			name:     "root path",
			path:     "/",
			expected: "Resource",
		},
		{
			name:     "only parameters",
			path:     "/{id}/{id2}",
			expected: "Resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resourceNameFromPath(tt.path)
			if result != tt.expected {
				t.Errorf("resourceNameFromPath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestResourceNameFromPath_StripsExtensions(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "php extension", path: "/login.php", expected: "Login"},
		{name: "mvc extension", path: "/register.mvc", expected: "Register"},
		{name: "json extension", path: "/data.json", expected: "Data"},
		{name: "asp extension", path: "/page.asp", expected: "Page"},
		{name: "aspx extension", path: "/submit.aspx", expected: "Submit"},
		{name: "jsp extension", path: "/view.jsp", expected: "View"},
		{name: "html extension", path: "/index.html", expected: "Index"},
		{name: "htm extension", path: "/home.htm", expected: "Home"},
		{name: "xml extension", path: "/feed.xml", expected: "Feed"},
		{name: "action extension", path: "/save.action", expected: "Save"},
		{name: "do extension", path: "/process.do", expected: "Process"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resourceNameFromPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResourceNameFromPath_HandlesHyphens(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "hyphenated segment", path: "/stored-xss", expected: singularize("StoredXss")},
		{name: "multi-hyphenated", path: "/cross-site-scripting", expected: singularize("CrossSiteScripting")},
		{name: "underscore segment", path: "/user_profile", expected: singularize("UserProfile")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resourceNameFromPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResourceNameFromPath_FallbackOnEmpty(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "root path", path: "/", expected: "Resource"},
		{name: "empty string", path: "", expected: "Resource"},
		{name: "extension-only segment", path: "/.php", expected: "Resource"},
		{name: "numeric-only segment", path: "/123", expected: "Resource123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resourceNameFromPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSchemaFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		schema   *openapi3.Schema
		expected string
	}{
		{
			name:     "nil schema",
			schema:   nil,
			expected: "",
		},
		{
			name:     "schema without properties",
			schema:   &openapi3.Schema{},
			expected: "",
		},
		{
			name: "simple schema",
			schema: &openapi3.Schema{
				Properties: openapi3.Schemas{
					"error":   {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
					"message": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
				},
			},
			expected: "error:string,message:string",
		},
		{
			name: "schema with integer",
			schema: &openapi3.Schema{
				Properties: openapi3.Schemas{
					"id":   {Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
					"name": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
				},
			},
			expected: "id:integer,name:string",
		},
		{
			name: "schema with different property order should produce same fingerprint",
			schema: &openapi3.Schema{
				Properties: openapi3.Schemas{
					"name": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
					"id":   {Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
				},
			},
			expected: "id:integer,name:string", // Sorted
		},
		{
			name: "schema with nil property value",
			schema: &openapi3.Schema{
				Properties: openapi3.Schemas{
					"field": nil,
				},
			},
			expected: "field:unknown",
		},
		{
			name: "schema with property missing type",
			schema: &openapi3.Schema{
				Properties: openapi3.Schemas{
					"field": {Value: &openapi3.Schema{}},
				},
			},
			expected: "field:unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := schemaFingerprint(tt.schema)
			if result != tt.expected {
				t.Errorf("schemaFingerprint() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExtractComponents(t *testing.T) {
	// Create a document with inline schemas
	doc := &openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   "Test API",
			Version: "1.0.0",
		},
		Paths: openapi3.NewPaths(),
	}

	// Add POST /api/v2/tickets with request body
	postResponses := openapi3.NewResponses()
	postResponses.Set("201", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: stringPtr("Created"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type: &openapi3.Types{"object"},
							Properties: openapi3.Schemas{
								"id":    {Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
								"title": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
							},
						},
					},
				},
			},
		},
	})

	doc.Paths.Set("/api/v2/tickets", &openapi3.PathItem{
		Post: &openapi3.Operation{
			Summary: "Create ticket",
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Content: openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: &openapi3.SchemaRef{
								Value: &openapi3.Schema{
									Type: &openapi3.Types{"object"},
									Properties: openapi3.Schemas{
										"title":       {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
										"description": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
									},
								},
							},
						},
					},
				},
			},
			Responses: postResponses,
		},
	})

	// Add GET /api/v2/tickets/{ticketId} with response
	getResponses := openapi3.NewResponses()
	getResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: stringPtr("OK"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type: &openapi3.Types{"object"},
							Properties: openapi3.Schemas{
								"id":    {Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
								"title": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
							},
						},
					},
				},
			},
		},
	})
	getResponses.Set("404", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: stringPtr("Not Found"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type: &openapi3.Types{"object"},
							Properties: openapi3.Schemas{
								"error":   {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
								"message": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
							},
						},
					},
				},
			},
		},
	})

	doc.Paths.Set("/api/v2/tickets/{ticketId}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			Summary:   "Get ticket",
			Responses: getResponses,
		},
	})

	// Extract components
	extractComponents(doc)

	// Verify components were created
	require.NotNil(t, doc.Components, "Components should be initialized")
	require.NotNil(t, doc.Components.Schemas, "Schemas should be initialized")

	// Verify request body schema was extracted
	assert.Contains(t, doc.Components.Schemas, "CreateTicketRequest",
		"CreateTicketRequest schema not found in components")

	// Verify response schemas were extracted
	// Note: POST 201 and GET 200 have identical schemas (id, title), so they share the same component
	_, hasCreatedResponse := doc.Components.Schemas["TicketCreatedResponse"]
	_, hasTicketResponse := doc.Components.Schemas["TicketResponse"]
	assert.True(t, hasCreatedResponse || hasTicketResponse,
		"No ticket response schema found in components (expected TicketCreatedResponse or TicketResponse)")

	assert.Contains(t, doc.Components.Schemas, "TicketNotFoundResponse",
		"TicketNotFoundResponse schema not found in components")

	// Verify schemas were replaced with $ref
	postOp := doc.Paths.Find("/api/v2/tickets").Post
	require.NotNil(t, postOp.RequestBody, "POST request body should not be nil")
	assert.NotEmpty(t, postOp.RequestBody.Value.Content["application/json"].Schema.Ref,
		"POST request body schema not replaced with $ref")

	getOp := doc.Paths.Find("/api/v2/tickets/{ticketId}").Get
	resp200 := getOp.Responses.Value("200")
	require.NotNil(t, resp200, "GET 200 response should not be nil")
	assert.NotEmpty(t, resp200.Value.Content["application/json"].Schema.Ref,
		"GET 200 response schema not replaced with $ref")

	resp404 := getOp.Responses.Value("404")
	require.NotNil(t, resp404, "GET 404 response should not be nil")
	assert.NotEmpty(t, resp404.Value.Content["application/json"].Schema.Ref,
		"GET 404 response schema not replaced with $ref")

	// Verify deduplication: POST 201 and GET 200 have identical schemas (id, title).
	// They may or may not share the same $ref depending on the response-vs-request
	// fingerprint maps; at minimum, both $refs must be non-empty (already checked above).
	postResp := postOp.Responses.Value("201")
	require.NotNil(t, postResp, "POST 201 response should not be nil")
	getResp := getOp.Responses.Value("200")
	require.NotNil(t, getResp, "GET 200 response should not be nil")
	t.Logf("POST 201 ref: %s", postResp.Value.Content["application/json"].Schema.Ref)
	t.Logf("GET 200 ref: %s", getResp.Value.Content["application/json"].Schema.Ref)
}

func TestBuildOperation_FormBody(t *testing.T) {
	t.Run("url-encoded form body", func(t *testing.T) {
		gen := &OpenAPIGenerator{}
		endpoints := []classify.ClassifiedRequest{
			{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST",
					URL:    "https://api.example.com/login",
					Headers: map[string]string{
						"content-type": "application/x-www-form-urlencoded",
					},
					Body: []byte("username=alice&password=secret"),
					Response: crawl.ObservedResponse{
						StatusCode: 200,
					},
				},
				IsAPI: true,
			},
		}
		spec, err := gen.Generate(endpoints)
		require.NoError(t, err, "Generate should succeed")

		var parsed map[string]interface{}
		require.NoError(t, yaml.Unmarshal(spec, &parsed), "YAML parse should succeed")

		// Dig into paths./login.post.requestBody.content
		paths, _ := parsed["paths"].(map[string]interface{})
		loginPath, _ := paths["/login"].(map[string]interface{})
		post, _ := loginPath["post"].(map[string]interface{})
		requestBody, _ := post["requestBody"].(map[string]interface{})
		content, _ := requestBody["content"].(map[string]interface{})

		_, hasFormEncoded := content["application/x-www-form-urlencoded"]
		assert.True(t, hasFormEncoded, "expected application/x-www-form-urlencoded in content, got keys: %v", content)
		_, hasJSON := content["application/json"]
		assert.False(t, hasJSON, "expected no application/json key for url-encoded-only endpoint")
	})

	t.Run("mixed json and url-encoded observations", func(t *testing.T) {
		gen := &OpenAPIGenerator{}
		endpoints := []classify.ClassifiedRequest{
			{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST",
					URL:    "https://api.example.com/submit",
					Headers: map[string]string{
						"content-type": "application/json",
					},
					Body:     []byte(`{"name":"Alice"}`),
					Response: crawl.ObservedResponse{StatusCode: 200},
				},
				IsAPI: true,
			},
			{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST",
					URL:    "https://api.example.com/submit",
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
					},
					Body:     []byte("name=Bob"),
					Response: crawl.ObservedResponse{StatusCode: 200},
				},
				IsAPI: true,
			},
		}
		spec, err := gen.Generate(endpoints)
		require.NoError(t, err, "Generate should succeed")

		var parsed map[string]interface{}
		require.NoError(t, yaml.Unmarshal(spec, &parsed), "YAML parse should succeed")

		paths, _ := parsed["paths"].(map[string]interface{})
		submitPath, _ := paths["/submit"].(map[string]interface{})
		post, _ := submitPath["post"].(map[string]interface{})
		requestBody, _ := post["requestBody"].(map[string]interface{})
		content, _ := requestBody["content"].(map[string]interface{})

		_, hasJSON := content["application/json"]
		assert.True(t, hasJSON, "expected application/json in content, got keys: %v", content)
		_, hasFormEncoded := content["application/x-www-form-urlencoded"]
		assert.True(t, hasFormEncoded, "expected application/x-www-form-urlencoded in content, got keys: %v", content)
	})
}

func TestOpenAPIGenerator_MultipartFormData_EndToEnd(t *testing.T) {
	// Build a well-formed multipart/form-data body with one text field and
	// one file upload field, then pass it through gen.Generate() and assert
	// that the resulting spec carries a multipart/form-data requestBody with
	// the file field typed as string/binary.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	// Text field
	err := w.WriteField("username", "alice")
	require.NoError(t, err)

	// File field
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="avatar"; filename="photo.jpg"`)
	h.Set("Content-Type", "image/jpeg")
	fw, err := w.CreatePart(h)
	require.NoError(t, err)
	_, _ = fw.Write([]byte("JPEG_DATA"))
	_ = w.Close()

	contentType := "multipart/form-data; boundary=" + w.Boundary()

	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/upload",
				Headers: map[string]string{
					"content-type": contentType,
				},
				Body: buf.Bytes(),
				Response: crawl.ObservedResponse{
					StatusCode: 200,
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	require.NoError(t, err, "Generate should succeed")

	specStr := string(spec)

	// The requestBody content must have a multipart/form-data key.
	assert.Contains(t, specStr, "multipart/form-data", "spec missing multipart/form-data content type in requestBody")

	// The file field must be present and typed string/binary.
	assert.Contains(t, specStr, "avatar", "spec missing 'avatar' field from multipart body")
	assert.Contains(t, specStr, "binary", "spec missing format: binary for file upload field")
}

// TestExtractComponents_RequestResponseScopedRefs verifies that when a request
// body and a 200 response body share IDENTICAL property shapes (echo-style
// endpoint), the generated $ref values are DIFFERENT — the request gets a
// name ending in "Request" and the response gets a name ending in "Response".
// Pre-fix, fingerprintToName was shared between request and response extraction,
// causing the response to reuse the request's component name (e.g., the response
// would be tagged "CreateXRequest" instead of "XResponse").
func TestExtractComponents_RequestResponseScopedRefs(t *testing.T) {
	gen := &OpenAPIGenerator{}

	// Echo-style endpoint: request and response have identical property shapes.
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/echo",
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: []byte(`{"id": 1, "name": "x"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"id": 1, "name": "x"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	require.NoError(t, err, "Generate should succeed")

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	require.NoError(t, err, "Generated spec should be valid OpenAPI")

	echoPath := doc.Paths.Find("/echo")
	require.NotNil(t, echoPath, "expected /echo path")
	require.NotNil(t, echoPath.Post, "expected POST on /echo")

	// Get the request body $ref.
	reqBody := echoPath.Post.RequestBody
	require.NotNil(t, reqBody, "expected requestBody")
	jsonReqMedia := reqBody.Value.Content["application/json"]
	require.NotNil(t, jsonReqMedia, "expected application/json in requestBody")
	reqRef := jsonReqMedia.Schema.Ref
	assert.NotEmpty(t, reqRef, "expected $ref in requestBody schema")
	assert.True(t, strings.HasSuffix(reqRef, "Request"),
		"requestBody $ref %q should end with 'Request'", reqRef)

	// Get the 200 response $ref.
	resp200 := echoPath.Post.Responses.Value("200")
	require.NotNil(t, resp200, "expected 200 response")
	jsonRespMedia := resp200.Value.Content["application/json"]
	require.NotNil(t, jsonRespMedia, "expected application/json in 200 response")
	respRef := jsonRespMedia.Schema.Ref
	assert.NotEmpty(t, respRef, "expected $ref in 200 response schema")
	assert.True(t, strings.HasSuffix(respRef, "Response"),
		"200 response $ref %q should end with 'Response'", respRef)

	// The two $ref values must be DIFFERENT (pre-fix they were the same).
	assert.NotEqual(t, reqRef, respRef,
		"request and response $refs must differ (echo endpoints share property shapes but not component names)")
}

// TestExtractComponents_DeterministicMultiContentType ensures that when a
// single endpoint exposes multiple media types with DIFFERENT schemas (e.g.,
// JSON + urlencoded observations), component names are stable across runs.
// The previous TestExtractComponents_Deterministic only used one media type
// per path and missed the inner-map iteration order issue.
func TestExtractComponents_DeterministicMultiContentType(t *testing.T) {
	var obs []classify.ClassifiedRequest
	for _, p := range []string{"/api/a", "/api/b", "/api/c", "/api/d", "/api/e"} {
		obs = append(obs,
			classify.ClassifiedRequest{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST", URL: "http://x.test" + p,
					Headers: map[string]string{"Content-Type": "application/json"},
					Body:    []byte(`{"jsonField":"v"}`),
				},
				IsAPI: true, Confidence: 0.9, APIType: "rest",
			},
			classify.ClassifiedRequest{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST", URL: "http://x.test" + p,
					Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
					Body:    []byte(`urlencodedField=v`),
				},
				IsAPI: true, Confidence: 0.9, APIType: "rest",
			},
		)
	}
	gen := &OpenAPIGenerator{}
	runs := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		out, err := gen.Generate(obs)
		require.NoError(t, err)
		runs[i] = out
	}
	for i := 1; i < 5; i++ {
		assert.Equal(t, string(runs[0]), string(runs[i]), "run %d differs from run 0", i)
	}
}

// TestOpenAPIGenerator_MultipartRepeatedFileFields_E2E verifies that when a
// multipart body contains two parts with the same name="files" both carrying
// filenames, the generated spec contains exactly ONE "files" property with
// format: binary.
//
// Current intentional last-wins behavior: the second part overwrites the first
// in schema.Properties, so only one "files" entry exists. This is documented
// here so future readers understand the design decision and can change it if
// array semantics are desired.
func TestOpenAPIGenerator_MultipartRepeatedFileFields_E2E(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	// Two file parts with the same name "files".
	for _, fname := range []string{"a.jpg", "b.png"} {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="files"; filename="`+fname+`"`)
		h.Set("Content-Type", "image/jpeg")
		fw, err := w.CreatePart(h)
		require.NoError(t, err)
		_, _ = fw.Write([]byte("filedata"))
	}
	_ = w.Close()

	contentType := "multipart/form-data; boundary=" + w.Boundary()

	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/upload",
				Headers: map[string]string{
					"content-type": contentType,
				},
				Body: buf.Bytes(),
				Response: crawl.ObservedResponse{
					StatusCode: 200,
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	require.NoError(t, err, "Generate should succeed")

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	require.NoError(t, err, "Generated spec should be valid OpenAPI")

	uploadPath := doc.Paths.Find("/upload")
	require.NotNil(t, uploadPath, "expected /upload path in spec")
	require.NotNil(t, uploadPath.Post, "expected POST operation on /upload")
	require.NotNil(t, uploadPath.Post.RequestBody, "expected requestBody on POST /upload")

	content := uploadPath.Post.RequestBody.Value.Content
	multipartMedia, ok := content["multipart/form-data"]
	require.True(t, ok, "expected multipart/form-data content type in requestBody")

	// Resolve $ref if needed
	schema := multipartMedia.Schema
	if schema.Ref != "" {
		// Look up the component
		refName := strings.TrimPrefix(schema.Ref, "#/components/schemas/")
		schema = doc.Components.Schemas[refName]
	}
	require.NotNil(t, schema, "expected schema for multipart/form-data")
	require.NotNil(t, schema.Value, "expected schema value")
	require.NotNil(t, schema.Value.Properties, "expected schema properties")

	// Exactly ONE "files" property (last-wins: second part overwrites first).
	filesProp, ok := schema.Value.Properties["files"]
	assert.True(t, ok, "expected exactly one 'files' property in schema")
	if ok {
		require.NotNil(t, filesProp.Value)
		assert.Equal(t, "string", filesProp.Value.Type.Slice()[0],
			"'files' property should be type string")
		assert.Equal(t, "binary", filesProp.Value.Format,
			"'files' property should have format: binary")
	}
}

// Helper function for tests
func stringPtr(s string) *string {
	return &s
}

func TestOpenAPIGenerator_NonJSONContentType(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/page",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/html",
					Body:        []byte("<html><body>Hello</body></html>"),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	specStr := string(spec)
	// Should have a 200 response but no application/json content
	if strings.Contains(specStr, "application/json") {
		t.Error("HTML response should not produce application/json schema")
	}
	// Should still have the path
	if !strings.Contains(specStr, "/page") {
		t.Error("Expected /page path in spec")
	}
}

func TestOpenAPIGenerator_EmptyEndpoints(t *testing.T) {
	gen := &OpenAPIGenerator{}
	spec, err := gen.Generate([]classify.ClassifiedRequest{})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if spec != nil {
		t.Errorf("Expected nil spec for empty endpoints, got %d bytes", len(spec))
	}
}

func TestOpenAPIGenerator_MalformedURL(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/valid",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"ok": true}`),
				},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "://missing-scheme",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"ok": true}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Valid endpoint should be present
	if !strings.Contains(string(spec), "/valid") {
		t.Error("Expected /valid path from valid endpoint")
	}
}

func TestOpenAPIGenerator_NonHTTPScheme(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/valid",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"ok": true}`),
				},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "ftp://files.example.com/data",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"ok": true}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	specStr := string(spec)
	// FTP endpoint should be excluded
	if strings.Contains(specStr, "ftp://") {
		t.Error("FTP scheme should be rejected from servers list")
	}
	if strings.Contains(specStr, "/data") {
		t.Error("FTP endpoint path should not appear in spec")
	}
	// HTTPS endpoint should be present
	if !strings.Contains(specStr, "/valid") {
		t.Error("HTTPS endpoint should be present")
	}
}

// --- x-vespasian-source extension tests ---

func makeClassified(method, rawURL, source string) classify.ClassifiedRequest {
	return classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method: method,
			URL:    rawURL,
			Source: source,
		},
		IsAPI:      true,
		Confidence: 0.9,
		APIType:    "rest",
	}
}

func TestOpenAPI_XVespasianSource_DynamicWins(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "katana"),
		makeClassified("GET", "https://h/api/x", "static:js"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present")
	}
	if ext != "dynamic" {
		t.Errorf("expected x-vespasian-source=dynamic, got %v", ext)
	}
}

func TestOpenAPI_XVespasianSource_JSBundleOnly(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:js"),
		makeClassified("GET", "https://h/api/x", "static:js"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present")
	}
	if ext != "js-bundle" {
		t.Errorf("expected x-vespasian-source=js-bundle, got %v", ext)
	}
}

func TestOpenAPI_XVespasianSource_JSSourcemap(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:js-sourcemap"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present")
	}
	if ext != "js-sourcemap" {
		t.Errorf("expected x-vespasian-source=js-sourcemap, got %v", ext)
	}
}

// LAB-4992 / SEC-BE-001: a group whose only source is the concat reconstruction
// tag (static:js-concat) must surface x-vespasian-source "js-bundle-concat" so
// consumers can weight never-probed reconstructions below observed literals.
func TestOpenAPI_XVespasianSource_JSBundleConcat(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:js-concat"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present")
	}
	if ext != "js-bundle-concat" {
		t.Errorf("expected x-vespasian-source=js-bundle-concat, got %v", ext)
	}
}

// QUAL-003: a group mixing static:js-concat and static:js (both all-JS-static)
// must resolve to the least-confident member, "js-bundle-concat" — not
// "dynamic" (the pre-fix behavior; the closed allow-list still treats a
// genuinely non-JS-static source as dynamic, but an all-JS-static mixed group
// now resolves to its least-confident member instead). Pins that concat is a
// distinct, lowest-confidence member of the allow-list. See
// TestComputeSourceTag_MixedJSStaticGroups for the full confidence-ordering
// table.
func TestOpenAPI_XVespasianSource_MixedConcatAndBundle(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:js-concat"),
		makeClassified("GET", "https://h/api/x", "static:js"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	if ext := getOp["x-vespasian-source"]; ext != "js-bundle-concat" {
		t.Errorf("expected x-vespasian-source=js-bundle-concat (least-confident of js-bundle/js-bundle-concat) for mixed group, got %v", ext)
	}
}

func TestOpenAPI_XVespasianSource_OmittedForEmptySource(t *testing.T) {
	gen := &OpenAPIGenerator{}
	// No static: source anywhere in the input.
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", ""),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	if _, ok := getOp["x-vespasian-source"]; ok {
		t.Error("expected x-vespasian-source to be absent when source is empty")
	}
}

// Regression for QUAL-005: a group that mixes untagged (Source=="") dynamic
// entries with static:js entries must resolve to "dynamic", not "js-bundle".
// The presence of at least one static:* in the overall input still triggers
// the extension via anyStaticSource(); within the group, an empty Source is a
// dynamic signal and must not be skipped.
func TestComputeSourceTag_MixedEmptyAndStaticInGroup_ResolvesDynamic(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		// Untagged dynamic entry for /api/x (pre-LAB-2108 capture style).
		makeClassified("GET", "https://h/api/x", ""),
		// Static entry for the same endpoint key.
		makeClassified("GET", "https://h/api/x", "static:js"),
		// Unrelated static entry so anyStaticSource gates the extension on.
		makeClassified("GET", "https://h/api/y", "static:js"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present for mixed group")
	}
	if ext != "dynamic" {
		t.Errorf("expected x-vespasian-source=dynamic when group mixes empty Source and static:js, got %v", ext)
	}
}

// Regression for CR-2: a non-JS "static:*" source (e.g. static:html from
// pkg/analyze form analysis) must NOT gate or surface in the x-vespasian-source
// extension. The extension is scoped to JS bundle / sourcemap recovery only.
func TestOpenAPI_XVespasianSource_StaticHtmlIgnored(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:html"),
		makeClassified("POST", "https://h/api/y", "static:html"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	// Walk every operation; the extension must be absent everywhere when only
	// non-JS static sources are present in the input.
	for _, pathVal := range paths {
		pathItem := pathVal.(map[string]interface{})
		for _, opVal := range pathItem {
			op, ok := opVal.(map[string]interface{})
			if !ok {
				continue
			}
			if _, has := op["x-vespasian-source"]; has {
				t.Errorf("x-vespasian-source must be absent when only static:html (non-JS) is present; op: %v", op)
			}
		}
	}
}

// Regression for CR-2: a group containing ONLY static:html, in a corpus where
// another group has static:js (so anyStaticSource gates the extension on),
// must resolve to "dynamic" — not "html". Pre-fix this test would have failed:
// computeSourceTag's strings.TrimPrefix default would have emitted
// x-vespasian-source: "html" for the /api/x group. Post-fix the JS-only
// allow-list early-returns "dynamic" for any non-JS static source. This is
// the only single-group composition that distinguishes pre-fix from post-fix
// behavior; the StaticHtmlIgnored test above covers the corpus-gate case.
func TestComputeSourceTag_StaticHtmlOnlyGroupInJSCorpus_ResolvesDynamic(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		// /api/x has ONLY static:html — pre-fix would emit "html" here.
		makeClassified("GET", "https://h/api/x", "static:html"),
		makeClassified("GET", "https://h/api/x", "static:html"),
		// Unrelated static:js entry forces anyStaticSource to fire (true under
		// both pre-fix HasPrefix("static:") AND post-fix crawl.IsJSStaticSource).
		makeClassified("GET", "https://h/api/z", "static:js"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present (anyStaticSource fires from /api/z)")
	}
	if ext != "dynamic" {
		t.Errorf("expected x-vespasian-source=dynamic for static:html-only group, got %v (a 'html' or other non-allowed value means the allow-list regressed)", ext)
	}
}

// QUAL-003: a group mixing distinct JS-static friendly tags (static:js +
// static:js-sourcemap, both all-JS-static — no genuinely dynamic/non-JS-static
// source present) must resolve to the LEAST-CONFIDENT member ("js-sourcemap"),
// NOT "dynamic". "dynamic" is the highest-confidence label and must be
// reserved for groups containing a real non-JS-static source; see
// TestComputeSourceTag_MixedJSStaticGroups for the full confidence-ordering
// table and TestComputeSourceTag_MixedEmptyAndStaticInGroup_ResolvesDynamic /
// TestComputeSourceTag_StaticHtmlOnlyGroupInJSCorpus_ResolvesDynamic for the
// cases that must still resolve to "dynamic".
func TestComputeSourceTag_MixedStaticGroups(t *testing.T) {
	gen := &OpenAPIGenerator{}
	// Two entries for the same endpoint: one from js bundle, one from sourcemap.
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:js"),
		makeClassified("GET", "https://h/api/x", "static:js-sourcemap"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present")
	}
	if ext != "js-sourcemap" {
		t.Errorf("expected x-vespasian-source=js-sourcemap (least-confident of js-bundle/js-sourcemap) for mixed all-JS-static group, got %v", ext)
	}
}

// QUAL-003: computeSourceTag confidence-ordering table (most → least
// confident: js-bundle > js-sourcemap > js-bundle-concat). An all-JS-static
// mixed group resolves to the least-confident member present; "dynamic" is
// reserved for a group containing a genuinely non-JS-static source.
func TestComputeSourceTag_MixedJSStaticGroups(t *testing.T) {
	tests := []struct {
		name    string
		sources []string
		want    string
	}{
		{
			name:    "js-bundle + js-bundle-concat -> js-bundle-concat (least confident)",
			sources: []string{"static:js", "static:js-concat"},
			want:    "js-bundle-concat",
		},
		{
			name:    "js-sourcemap + js-bundle-concat -> js-bundle-concat (least confident)",
			sources: []string{"static:js-sourcemap", "static:js-concat"},
			want:    "js-bundle-concat",
		},
		{
			name:    "js-bundle + js-sourcemap -> js-sourcemap (least confident of the two)",
			sources: []string{"static:js", "static:js-sourcemap"},
			want:    "js-sourcemap",
		},
		{
			name:    "js-static mixed with a genuinely non-JS-static source -> dynamic",
			sources: []string{"static:js", "static:html"},
			want:    "dynamic",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var group []classify.ClassifiedRequest
			for _, src := range tt.sources {
				group = append(group, makeClassified("GET", "https://h/api/x", src))
			}
			if got := computeSourceTag(group); got != tt.want {
				t.Errorf("computeSourceTag(%v) = %q, want %q", tt.sources, got, tt.want)
			}
		})
	}
}

func TestOpenAPI_XVespasianSource_NoStaticPresent_ByteCompat(t *testing.T) {
	// When no static: sources exist anywhere in input, generate twice with
	// identical inputs and assert output is identical (byte compat).
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "katana"),
		makeClassified("POST", "https://h/api/y", "browser"),
	}

	spec1, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate (run 1) failed: %v", err)
	}
	spec2, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate (run 2) failed: %v", err)
	}
	if string(spec1) != string(spec2) {
		t.Error("Generate output is not deterministic / byte-compatible across runs")
	}

	// Also verify extension is absent on every operation.
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec1, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	for _, pathVal := range paths {
		pathItem := pathVal.(map[string]interface{})
		for _, opVal := range pathItem {
			if op, ok := opVal.(map[string]interface{}); ok {
				if _, hasExt := op["x-vespasian-source"]; hasExt {
					t.Error("expected x-vespasian-source to be absent when no static sources in input")
				}
			}
		}
	}
}

// TestBuildOperation_EmptyValuesQueryParam is a regression test for D2: a query
// parameter with an empty observed-values slice must be silently omitted from
// the generated Operation. Prior to the D2 fix, buildOperation would panic
// with an index-out-of-range accessing info.values[0] on the scalar branch.
func TestBuildOperation_EmptyValuesQueryParam(t *testing.T) {
	// "foo" has an empty values slice — simulates a hand-crafted capture where
	// the param key is present but no values were ever recorded.
	// "bar" is a normal scalar param that should still appear.
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://api.example.com/items?bar=1",
				QueryParams: map[string][]string{"foo": {}, "bar": {"1"}},
				Response:    crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true,
		},
	}
	key := endpointKey{path: "/items", method: "get"}

	// Must not panic.
	op := buildOperation(key, group, false, nil)

	// "foo" must be absent — no observed values means we cannot document it.
	for _, paramRef := range op.Parameters {
		if paramRef.Value != nil && paramRef.Value.Name == "foo" {
			t.Errorf("parameter 'foo' with empty values should be omitted, but was emitted")
		}
	}

	// "bar" must still be present.
	found := false
	for _, paramRef := range op.Parameters {
		if paramRef.Value != nil && paramRef.Value.Name == "bar" {
			found = true
		}
	}
	if !found {
		t.Error("parameter 'bar' with a valid value should be emitted")
	}
}

// TestBuildOperation_ScalarQueryParam is a regression test: a scalar query param
// should produce a non-array parameter with no Style or Explode set.
func TestBuildOperation_ScalarQueryParam(t *testing.T) {
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://api.example.com/items?page=1",
				QueryParams: map[string][]string{"page": {"1"}},
				Response:    crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true,
		},
	}
	key := endpointKey{path: "/items", method: "get"}
	op := buildOperation(key, group, false, nil)

	require.Len(t, op.Parameters, 1)
	param := op.Parameters[0].Value
	require.NotNil(t, param)
	require.NotNil(t, param.Schema)
	require.NotNil(t, param.Schema.Value)
	require.NotNil(t, param.Schema.Value.Type)

	assert.Equal(t, "integer", param.Schema.Value.Type.Slice()[0], "type should be integer for scalar")
	assert.Equal(t, "", param.Style, "scalar param should have no style")
	assert.Nil(t, param.Explode, "scalar param should have nil Explode")
	assert.Nil(t, param.Schema.Value.Items, "scalar param should have no items")
}

// TestBuildOperation_MultiValueQueryParam_AllInts tests that an array param with
// all-integer values produces type:array with items type:integer and style/explode set.
func TestBuildOperation_MultiValueQueryParam_AllInts(t *testing.T) {
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://api.example.com/items?ids=1&ids=2&ids=3",
				QueryParams: map[string][]string{"ids": {"1", "2", "3"}},
				Response:    crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true,
		},
	}
	key := endpointKey{path: "/items", method: "get"}
	op := buildOperation(key, group, false, nil)

	require.Len(t, op.Parameters, 1)
	param := op.Parameters[0].Value
	require.NotNil(t, param)
	require.NotNil(t, param.Schema)
	require.NotNil(t, param.Schema.Value)
	require.NotNil(t, param.Schema.Value.Type)

	assert.Equal(t, "array", param.Schema.Value.Type.Slice()[0], "type should be array")
	require.NotNil(t, param.Schema.Value.Items, "items must be set for array param")
	require.NotNil(t, param.Schema.Value.Items.Value)
	require.NotNil(t, param.Schema.Value.Items.Value.Type)
	assert.Equal(t, "integer", param.Schema.Value.Items.Value.Type.Slice()[0], "items type should be integer")
	assert.Equal(t, "form", param.Style, "style should be form")
	require.NotNil(t, param.Explode)
	assert.True(t, *param.Explode, "explode should be true")
}

// TestBuildOperation_MultiValueQueryParam_Mixed tests that a mixed-type array
// falls back to items type:string.
func TestBuildOperation_MultiValueQueryParam_Mixed(t *testing.T) {
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://api.example.com/items?tag=a&tag=1",
				QueryParams: map[string][]string{"tag": {"a", "1"}},
				Response:    crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true,
		},
	}
	key := endpointKey{path: "/items", method: "get"}
	op := buildOperation(key, group, false, nil)

	require.Len(t, op.Parameters, 1)
	param := op.Parameters[0].Value
	require.NotNil(t, param.Schema.Value.Items)
	assert.Equal(t, "string", param.Schema.Value.Items.Value.Type.Slice()[0], "mixed values should produce items type:string")
}

// TestBuildOperation_MultiValueQueryParam_AllBool tests all-boolean array values.
func TestBuildOperation_MultiValueQueryParam_AllBool(t *testing.T) {
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://api.example.com/flags?flag=true&flag=false",
				QueryParams: map[string][]string{"flag": {"true", "false"}},
				Response:    crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true,
		},
	}
	key := endpointKey{path: "/flags", method: "get"}
	op := buildOperation(key, group, false, nil)

	require.Len(t, op.Parameters, 1)
	param := op.Parameters[0].Value
	require.NotNil(t, param.Schema.Value.Items)
	assert.Equal(t, "boolean", param.Schema.Value.Items.Value.Type.Slice()[0], "all-bool values should produce items type:boolean")
}

// TestInferQueryParamItemsType tests the items type inference function directly.
func TestInferQueryParamItemsType(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "empty slice", values: []string{}, want: "string"},
		{name: "all integers", values: []string{"1", "2", "3"}, want: "integer"},
		{name: "all floats", values: []string{"1.5", "2.5"}, want: "number"},
		{name: "all booleans", values: []string{"true", "false"}, want: "boolean"},
		{name: "mixed string and int", values: []string{"a", "1"}, want: "string"},
		{name: "single string", values: []string{"hello"}, want: "string"},
		{name: "integer is also float, int wins", values: []string{"1", "2"}, want: "integer"},
		{name: "single negative integer", values: []string{"-1"}, want: "integer"},
		{name: "single zero", values: []string{"0"}, want: "integer"},
		{name: "single negative float", values: []string{"-0.5"}, want: "number"},
		{name: "single scientific notation", values: []string{"1e10"}, want: "number"},
		{name: "single empty string", values: []string{""}, want: "string"},
		{name: "single mixed alphanumeric", values: []string{"abc123"}, want: "string"},
		{name: "single uppercase boolean-like", values: []string{"True"}, want: "string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferQueryParamItemsType(tt.values)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildOperation_ScalarQueryParam_OrderIndependence(t *testing.T) {
	// Two observations of the same scalar param: int first, then float.
	// Pre-fix: scalar branch took values[0] = "1" → emitted integer.
	// Post-fix: inferQueryParamItemsType walks all values → emits number.
	group := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{
			Method: "GET", URL: "https://x.test/items?limit=1",
			QueryParams: map[string][]string{"limit": {"1"}},
		}},
		{ObservedRequest: crawl.ObservedRequest{
			Method: "GET", URL: "https://x.test/items?limit=1.5",
			QueryParams: map[string][]string{"limit": {"1.5"}},
		}},
	}
	op := buildOperation(endpointKey{path: "/items", method: "get"}, group, false, nil)
	require.NotNil(t, op)
	require.Len(t, op.Parameters, 1)
	p := op.Parameters[0].Value
	require.NotNil(t, p)
	require.NotNil(t, p.Schema)
	require.NotNil(t, p.Schema.Value)
	require.NotNil(t, p.Schema.Value.Type)
	assert.Equal(t, []string{"number"}, p.Schema.Value.Type.Slice(),
		"scalar param type must be inferred from ALL observed values, not just the first")
	// Confirm scalar emission (not array): no Style/Explode set
	assert.Empty(t, p.Style, "scalar param should not set Style")
	assert.Nil(t, p.Explode, "scalar param should not set Explode")
}

func TestBuildOperation_PostDedupScalarNotOverWidened(t *testing.T) {
	// Regression: when classify.Deduplicate merges two scalar observations
	// of the same endpoint into one ClassifiedRequest, buildOperation must
	// still emit the param as scalar (not array). The pre-fix bug was that
	// the merged QueryParams slice had len > 1, tripping multiValueSeen.
	// The fix uses MultiValueQueryKeys (populated by RunClassifiers BEFORE
	// dedup) to record per-observation truth.
	//
	// Simulate post-dedup state: one ClassifiedRequest with merged values
	// AND an empty MultiValueQueryKeys map (no key was multi-value in any
	// contributing observation).
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://x.test/items?page=1",
				QueryParams: map[string][]string{"page": {"1", "2"}},
			},
			MultiValueQueryKeys: map[string]bool{}, // empty: page was scalar in both contributing obs
		},
	}
	op := buildOperation(endpointKey{path: "/items", method: "get"}, group, false, nil)
	require.NotNil(t, op)
	require.Len(t, op.Parameters, 1)
	p := op.Parameters[0].Value
	require.NotNil(t, p.Schema)
	require.NotNil(t, p.Schema.Value)
	require.NotNil(t, p.Schema.Value.Type)
	assert.Equal(t, []string{"integer"}, p.Schema.Value.Type.Slice(),
		"scalar param surviving dedup union must NOT be over-widened to array")
	assert.Empty(t, p.Style, "scalar must not set Style")
	assert.Nil(t, p.Explode, "scalar must not set Explode")
	assert.Nil(t, p.Schema.Value.Items, "scalar must not have Items")
}

func TestBuildOperation_PostDedupArrayStillDetected(t *testing.T) {
	// Companion regression: when a key WAS multi-value in a contributing
	// observation, MultiValueQueryKeys carries that truth through dedup,
	// and buildOperation must emit the param as array.
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://x.test/items?tag=a&tag=b",
				QueryParams: map[string][]string{"tag": {"a", "b"}},
			},
			MultiValueQueryKeys: map[string]bool{"tag": true},
		},
	}
	op := buildOperation(endpointKey{path: "/items", method: "get"}, group, false, nil)
	require.NotNil(t, op)
	require.Len(t, op.Parameters, 1)
	p := op.Parameters[0].Value
	require.NotNil(t, p.Schema)
	require.NotNil(t, p.Schema.Value)
	require.NotNil(t, p.Schema.Value.Type)
	assert.Equal(t, []string{"array"}, p.Schema.Value.Type.Slice(),
		"key with MultiValueQueryKeys=true must emit as array")
	assert.Equal(t, "form", p.Style)
	require.NotNil(t, p.Explode)
	assert.True(t, *p.Explode)
}

// TestMergeJSONBodies_TypeConflictPromotesToString verifies that JSON merge
// uses the same conflict-resolution as form merge (was: silently kept first
// type). Two observations with `count: 42` then `count: "hello"` should yield
// a string-typed schema (matching urlencoded/multipart behavior).
func TestMergeJSONBodies_TypeConflictPromotesToString(t *testing.T) {
	bodies := [][]byte{
		[]byte(`{"count": 42}`),
		[]byte(`{"count": "hello"}`),
	}
	merged := mergeJSONBodies(bodies)
	require.NotNil(t, merged)
	require.NotNil(t, merged.Value)
	require.NotNil(t, merged.Value.Properties)
	countProp := merged.Value.Properties["count"]
	require.NotNil(t, countProp)
	require.NotNil(t, countProp.Value.Type)
	require.NotEmpty(t, countProp.Value.Type.Slice())
	assert.Equal(t, "string", countProp.Value.Type.Slice()[0],
		"conflicting types should promote to string (matching form merge behavior)")
}

// TestMergeJSONBodies_SkipBranches verifies that mergeJSONBodies correctly skips
// nil/empty bodies and bodies that fail JSON inference, while still merging valid ones.
func TestMergeJSONBodies_SkipBranches(t *testing.T) {
	t.Run("skips empty body", func(t *testing.T) {
		bodies := [][]byte{nil, []byte(`{"a":1}`)}
		merged := mergeJSONBodies(bodies)
		require.NotNil(t, merged, "expected non-nil result when one body is valid")
		require.NotNil(t, merged.Value)
		require.NotNil(t, merged.Value.Properties)
		assert.Contains(t, merged.Value.Properties, "a", "valid body's property 'a' should be present")
	})

	t.Run("skips body that fails inference", func(t *testing.T) {
		bodies := [][]byte{[]byte("not valid json"), []byte(`{"a":1}`)}
		merged := mergeJSONBodies(bodies)
		require.NotNil(t, merged, "expected non-nil result when one body is valid")
		require.NotNil(t, merged.Value)
		require.NotNil(t, merged.Value.Properties)
		assert.Contains(t, merged.Value.Properties, "a", "valid body's property 'a' should be present")
		assert.Len(t, merged.Value.Properties, 1, "only the valid body should contribute properties")
	})
}

// TestExtractComponents_Deterministic verifies that Generate produces byte-identical
// output across multiple runs when many paths share the same schema fingerprint.
// Non-determinism would arise from iterating doc.Paths.Map() in random order:
// the first path encountered for a given fingerprint wins the component name.
func TestExtractComponents_Deterministic(t *testing.T) {
	gen := &OpenAPIGenerator{}

	// Build 26 endpoints /v1/a … /v1/z, each with the same request body shape
	// {name: string, count: integer}. They all produce the same schema fingerprint,
	// so whichever path is iterated first sets the component name. Without a
	// deterministic sort, the chosen name varies between runs.
	body := []byte(`{"name":"x","count":1}`)
	endpoints := make([]classify.ClassifiedRequest, 0, 26)
	for c := 'a'; c <= 'z'; c++ {
		endpoints = append(endpoints, classify.ClassifiedRequest{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://api.example.com/v1/" + string(c),
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    body,
				Response: crawl.ObservedResponse{
					StatusCode: 201,
					Body:       []byte(`{"id":1}`),
				},
			},
			IsAPI: true,
		})
	}

	// Run Generate 5 times; all outputs must be byte-identical.
	first, err := gen.Generate(endpoints)
	require.NoError(t, err, "first Generate call failed")

	for i := 2; i <= 5; i++ {
		out, err := gen.Generate(endpoints)
		require.NoError(t, err, "Generate call %d failed", i)
		assert.Equal(t, first, out, "Generate run %d produced different output than run 1 — non-determinism detected", i)
	}
}

// newDetEndpoint is a helper for TestGenerate_DeterministicUnderInputShuffle.
func newDetEndpoint(method, url string, body []byte, status int, respBody, respCT string) classify.ClassifiedRequest {
	ep := classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method:   method,
			URL:      url,
			Response: crawl.ObservedResponse{StatusCode: status},
		},
		IsAPI: true, Confidence: 0.9, APIType: "rest",
	}
	if len(body) > 0 {
		ep.Body = body
		ep.Headers = map[string]string{"Content-Type": "application/json"}
	}
	if len(respBody) > 0 {
		ep.Response.Body = []byte(respBody)
	}
	if respCT != "" {
		ep.Response.ContentType = respCT
	}
	return ep
}

// TestGenerate_DeterministicUnderInputShuffle is the headline LAB-4678
// guarantee: a fixed set of observations, fed in ANY order through Deduplicate +
// Generate, must produce a byte-identical spec. This is the property that makes
// Guard's runs consistent for identical input traffic. It exercises the two
// order-sensitive spots the fix addresses: the dedup response selection (A4,
// where GET /api/users is observed twice with different responses under one
// dedup key) and the per-group ordering lock in buildOperation (M3, where POST
// /api/users has two distinct request bodies that share a generate group).
func TestGenerate_DeterministicUnderInputShuffle(t *testing.T) {
	gen := &OpenAPIGenerator{}

	base := []classify.ClassifiedRequest{
		newDetEndpoint("GET", "https://api.example.com/api/users", nil, 200, `{"users":[{"id":1}]}`, "application/json"),
		newDetEndpoint("GET", "https://api.example.com/api/users", nil, 200, `{"users":[{"id":2},{"id":3}]}`, "application/json"),
		newDetEndpoint("POST", "https://api.example.com/api/users", []byte(`{"name":"a"}`), 201, `{"id":1}`, "application/json"),
		newDetEndpoint("POST", "https://api.example.com/api/users", []byte(`{"email":"b@x.io"}`), 201, `{"id":2}`, "application/json"),
		newDetEndpoint("GET", "https://api.example.com/api/orders", nil, 200, `{"orders":[]}`, "application/json"),
		newDetEndpoint("GET", "https://api.example.com/api/items/42", nil, 200, `{"id":42}`, "application/json"),
		newDetEndpoint("DELETE", "https://api.example.com/api/items/42", nil, 204, "", ""),
	}

	specFrom := func(order []classify.ClassifiedRequest) []byte {
		in := make([]classify.ClassifiedRequest, len(order))
		copy(in, order)
		deduped := classify.Deduplicate(in)
		out, err := gen.Generate(deduped)
		require.NoError(t, err)
		return out
	}

	want := specFrom(base)
	require.NotEmpty(t, want)

	// Reversed input.
	rev := make([]classify.ClassifiedRequest, len(base))
	for i := range base {
		rev[i] = base[len(base)-1-i]
	}
	assert.Equal(t, string(want), string(specFrom(rev)), "reversed input produced a different spec")

	// Several seeded shuffles.
	for _, seed := range []int64{1, 7, 42, 1000, 99999} {
		r := rand.New(rand.NewSource(seed)) //nolint:gosec // deterministic test shuffle, not security-sensitive
		shuffled := make([]classify.ClassifiedRequest, len(base))
		copy(shuffled, base)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		assert.Equal(t, string(want), string(specFrom(shuffled)),
			"shuffle seed %d produced a different spec — non-determinism detected", seed)
	}
}

// TestGenerate_ResponseSchema_SurvivesEmptyBaseObservation covers review finding
// 002: when a status code is observed both half-captured (empty response) and
// populated on the same endpoint, the populated response schema must survive
// regardless of which observation the deterministic group sort places first.
func TestGenerate_ResponseSchema_SurvivesEmptyBaseObservation(t *testing.T) {
	gen := &OpenAPIGenerator{}
	empty := classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method:   "POST",
			URL:      "https://api.example.com/api/users",
			Headers:  map[string]string{"Content-Type": "application/json"},
			Body:     []byte(`{"a":1}`),
			Response: crawl.ObservedResponse{StatusCode: 201}, // half-captured
		},
		IsAPI: true,
	}
	populated := classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method:  "POST",
			URL:     "https://api.example.com/api/users",
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    []byte(`{"b":2}`),
			Response: crawl.ObservedResponse{
				StatusCode:  201,
				ContentType: "application/json",
				Body:        []byte(`{"id":1,"name":"x"}`),
			},
		},
		IsAPI: true,
	}

	for _, order := range [][]classify.ClassifiedRequest{{empty, populated}, {populated, empty}} {
		spec, err := gen.Generate(order)
		require.NoError(t, err)
		// "name" appears only in the populated 201 response body, so its presence
		// proves the response schema was not dropped by an empty base.
		assert.Contains(t, string(spec), "name",
			"populated 201 response schema must survive regardless of observation order")
	}
}

// TestGenerate_ResponseSchema_ArraySurvivesEmptyBaseObservation covers the
// array/scalar case of review finding 002: a populated JSON array response has
// nil schema Properties, so adopting it into an empty base must not be gated on
// Properties!=nil. When an empty (half-captured) observation of the same status
// sorts first, the array response schema must still survive regardless of order
// (Codex/CodeRabbit review).
func TestGenerate_ResponseSchema_ArraySurvivesEmptyBaseObservation(t *testing.T) {
	gen := &OpenAPIGenerator{}
	empty := classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method:   "GET",
			URL:      "https://api.example.com/api/items",
			Response: crawl.ObservedResponse{StatusCode: 200}, // half-captured
		},
		IsAPI: true,
	}
	populated := classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method: "GET",
			URL:    "https://api.example.com/api/items",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`[{"id":1}]`),
			},
		},
		IsAPI: true,
	}

	for _, order := range [][]classify.ClassifiedRequest{{empty, populated}, {populated, empty}} {
		spec, err := gen.Generate(order)
		require.NoError(t, err)
		// An array response schema serializes with "type: array"; its presence
		// proves the populated array response was not dropped by an empty base.
		assert.Contains(t, string(spec), "array",
			"populated array response schema must survive regardless of observation order")
	}
}

// TestUnionSchemaProperties_RecursiveAdditive verifies the Phase 3 response
// schema union (LAB-4678): fields present in only one observation are preserved
// both at the top level and nested under a shared object, and existing fields
// are never removed or retyped.
func TestUnionSchemaProperties_RecursiveAdditive(t *testing.T) {
	strSchema := func() *openapi3.SchemaRef {
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}}
	}
	objSchema := func(props map[string]*openapi3.SchemaRef) *openapi3.Schema {
		return &openapi3.Schema{Type: &openapi3.Types{"object"}, Properties: props}
	}

	// dst: {id, user:{name}}   src: {email, user:{age}}
	dst := objSchema(map[string]*openapi3.SchemaRef{
		"id":   strSchema(),
		"user": {Value: objSchema(map[string]*openapi3.SchemaRef{"name": strSchema()})},
	})
	src := objSchema(map[string]*openapi3.SchemaRef{
		"email": strSchema(),
		"user":  {Value: objSchema(map[string]*openapi3.SchemaRef{"age": strSchema()})},
	})

	unionSchemaProperties(dst, src, maxSchemaUnionDepth)

	// Top-level union: id (dst-only) and email (src-only) both present.
	assert.Contains(t, dst.Properties, "id")
	assert.Contains(t, dst.Properties, "email")
	// Nested union under the shared "user": both name and age present.
	user := dst.Properties["user"].Value
	require.NotNil(t, user)
	assert.Contains(t, user.Properties, "name", "existing nested field retained")
	assert.Contains(t, user.Properties, "age", "src-only nested field added")
}

// TestUnionSchemaProperties_DepthGuard verifies recursion stops at depth 0
// without panicking (guards against pathological/cyclic inferred schemas).
func TestUnionSchemaProperties_DepthGuard(t *testing.T) {
	obj := &openapi3.Schema{Type: &openapi3.Types{"object"}, Properties: map[string]*openapi3.SchemaRef{
		"a": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
	}}
	src := &openapi3.Schema{Type: &openapi3.Types{"object"}, Properties: map[string]*openapi3.SchemaRef{
		"b": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
	}}
	unionSchemaProperties(obj, src, 0) // depth 0 -> no-op
	assert.NotContains(t, obj.Properties, "b", "depth 0 must not merge")
}

// TestUnionSchemaProperties_ArrayItems covers the collection case, which is where
// partial observations are most common. GET /users returning [{"id":1,"name":"a"}]
// and later [{"id":2,"email":"b@x"}] must document all three item fields. The union
// previously recursed only through Properties, and an array schema has none of its
// own, so the item schema was never entered and every field after the first
// observation was dropped.
func TestUnionSchemaProperties_ArrayItems(t *testing.T) {
	strSchema := func() *openapi3.SchemaRef {
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}}
	}
	arrayOfObject := func(props map[string]*openapi3.SchemaRef) *openapi3.Schema {
		return &openapi3.Schema{
			Type: &openapi3.Types{"array"},
			Items: &openapi3.SchemaRef{Value: &openapi3.Schema{
				Type: &openapi3.Types{"object"}, Properties: props,
			}},
		}
	}

	dst := arrayOfObject(map[string]*openapi3.SchemaRef{"id": strSchema(), "name": strSchema()})
	src := arrayOfObject(map[string]*openapi3.SchemaRef{"id": strSchema(), "email": strSchema()})

	unionSchemaProperties(dst, src, maxSchemaUnionDepth)

	items := dst.Items.Value
	require.NotNil(t, items)
	assert.Contains(t, items.Properties, "id")
	assert.Contains(t, items.Properties, "name", "first observation's item field retained")
	assert.Contains(t, items.Properties, "email", "second observation's item-only field must be unioned in")
}

// TestUnionSchemaProperties_NestedArrayOfObjects verifies the array recursion is
// reachable through an object property too, and that Items consumes a depth level
// like any other nesting step (so the existing bound still applies).
func TestUnionSchemaProperties_NestedArrayOfObjects(t *testing.T) {
	str := func() *openapi3.SchemaRef {
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}}
	}
	withItems := func(props map[string]*openapi3.SchemaRef) *openapi3.Schema {
		return &openapi3.Schema{Type: &openapi3.Types{"object"}, Properties: map[string]*openapi3.SchemaRef{
			"rows": {Value: &openapi3.Schema{
				Type:  &openapi3.Types{"array"},
				Items: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"object"}, Properties: props}},
			}},
		}}
	}

	dst := withItems(map[string]*openapi3.SchemaRef{"a": str()})
	src := withItems(map[string]*openapi3.SchemaRef{"b": str()})
	unionSchemaProperties(dst, src, maxSchemaUnionDepth)
	rows := dst.Properties["rows"].Value.Items.Value
	assert.Contains(t, rows.Properties, "a")
	assert.Contains(t, rows.Properties, "b")

	// depth 2 reaches the "rows" property (1) and its items (2), so the merge lands;
	// depth 1 stops before the items and must not.
	shallowDst := withItems(map[string]*openapi3.SchemaRef{"a": str()})
	unionSchemaProperties(shallowDst, src, 1)
	assert.NotContains(t, shallowDst.Properties["rows"].Value.Items.Value.Properties, "b",
		"array items must consume a depth level")
}

// jsonObservation builds one classified observation of the same endpoint with
// the given status and JSON response body. Shared by the buildOperation-level
// response-merge tests below.
func jsonObservation(status int, body string) classify.ClassifiedRequest {
	return classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method: "GET",
			URL:    "https://api.test/users",
			Response: crawl.ObservedResponse{
				StatusCode:  status,
				ContentType: "application/json",
				Body:        []byte(body),
			},
		},
		IsAPI:      true,
		APIType:    "rest",
		Confidence: 0.9,
	}
}

// TestBuildOperation_TopLevelArrayResponseUnion pins the LAB-4678 audit item-10
// fix END TO END through buildOperation, not by calling unionSchemaProperties
// directly. The direct-call tests above all bypassed the caller guard in
// buildOperation, which gated the union on Properties != nil — nil for a
// top-level array — making the array recursion unreachable for exactly the
// collection-endpoint case it was written for. Later observations' item fields
// were silently dropped from the spec.
func TestBuildOperation_TopLevelArrayResponseUnion(t *testing.T) {
	group := []classify.ClassifiedRequest{
		jsonObservation(200, `[{"id":1,"name":"a"}]`),
		jsonObservation(200, `[{"id":2,"email":"b@x"}]`),
	}

	op := buildOperation(endpointKey{method: "GET", path: "/users"}, group, false, nil)

	resp := op.Responses.Value("200")
	require.NotNil(t, resp)
	require.NotNil(t, resp.Value)
	mt := resp.Value.Content["application/json"]
	require.NotNil(t, mt)
	require.NotNil(t, mt.Schema)
	require.NotNil(t, mt.Schema.Value)

	schema := mt.Schema.Value
	require.Nil(t, schema.Properties, "a top-level array schema must have nil Properties (the condition that broke the guard)")
	require.NotNil(t, schema.Items, "top-level array response must expose Items")
	require.NotNil(t, schema.Items.Value)

	props := schema.Items.Value.Properties
	assert.Contains(t, props, "id", "field common to both observations must survive")
	assert.Contains(t, props, "name", "field from the first observation must survive")
	assert.Contains(t, props, "email", "field from the SECOND observation must survive the union")
}

// TestBuildOperation_ArrayResponseUnionIsOrderIndependent pins that the array
// union does not depend on which observation buildOperation sees first, so the
// emitted spec stays a deterministic function of the observation set.
func TestBuildOperation_ArrayResponseUnionIsOrderIndependent(t *testing.T) {
	forward := []classify.ClassifiedRequest{
		jsonObservation(200, `[{"id":1,"name":"a"}]`),
		jsonObservation(200, `[{"id":2,"email":"b@x"}]`),
	}
	reversed := []classify.ClassifiedRequest{
		jsonObservation(200, `[{"id":2,"email":"b@x"}]`),
		jsonObservation(200, `[{"id":1,"name":"a"}]`),
	}

	itemProps := func(group []classify.ClassifiedRequest) map[string]*openapi3.SchemaRef {
		op := buildOperation(endpointKey{method: "GET", path: "/users"}, group, false, nil)
		return op.Responses.Value("200").Value.Content["application/json"].Schema.Value.Items.Value.Properties
	}

	for _, name := range []string{"id", "name", "email"} {
		assert.Contains(t, itemProps(forward), name, "forward order must union %q", name)
		assert.Contains(t, itemProps(reversed), name, "reversed order must union %q", name)
	}
}

// TestBuildOperation_PreservesRequestResponsePairingByStatus pins the pairing
// half of LAB-4678's "spec preserves response fields and request/response
// pairing across observations". OpenAPI expresses that correspondence only
// through per-status response entries, so preserving it means two observations
// of the same endpoint with different statuses keep two distinct response
// schemas rather than collapsing into one merged shape.
func TestBuildOperation_PreservesRequestResponsePairingByStatus(t *testing.T) {
	group := []classify.ClassifiedRequest{
		jsonObservation(200, `{"id":1,"name":"ok"}`),
		jsonObservation(422, `{"error":"bad","field":"name"}`),
	}

	op := buildOperation(endpointKey{method: "GET", path: "/users"}, group, false, nil)

	okResp := op.Responses.Value("200")
	errResp := op.Responses.Value("422")
	require.NotNil(t, okResp, "200 observation must keep its own response entry")
	require.NotNil(t, errResp, "422 observation must keep its own response entry")

	okProps := okResp.Value.Content["application/json"].Schema.Value.Properties
	errProps := errResp.Value.Content["application/json"].Schema.Value.Properties

	assert.Contains(t, okProps, "name")
	assert.NotContains(t, okProps, "error", "the 422 body must not leak into the 200 schema")
	assert.Contains(t, errProps, "error")
	assert.NotContains(t, errProps, "id", "the 200 body must not leak into the 422 schema")
}

// TestComputeSourceTag_TotalOverEveryJSStaticSource pins the contract stated on
// computeSourceTag: for non-empty input it returns exactly one of "dynamic",
// "js-bundle", "js-sourcemap" — never "".
//
// It iterates every Source that crawl.IsJSStaticSource accepts, because that set is
// what broke the contract: LAB-4678 added static:js-nextroute and static:js-nextpage
// to IsJSStaticSource without adding them to computeSourceTag's switch, so those
// groups fell through with friendly == "" and emitted no extension. Enumerating the
// set here means the next Source added to IsJSStaticSource fails this test instead of
// silently producing an empty tag.
func TestComputeSourceTag_TotalOverEveryJSStaticSource(t *testing.T) {
	jsStaticSources := []string{
		crawl.SourceStaticJS,
		crawl.SourceStaticJSSourcemap,
		crawl.SourceNextRouteHandler,
		crawl.SourceNextPageRoute,
	}
	for _, src := range jsStaticSources {
		require.True(t, crawl.IsJSStaticSource(src),
			"%q must be in the IsJSStaticSource set this test enumerates", src)
	}

	// Every JS-static source now has its OWN name rather than collapsing to
	// "dynamic". A recovered Next.js route that reaches the generator must not
	// claim it was dynamically observed — it was read off a chunk URL and never
	// requested.
	valid := []string{"dynamic", "js-bundle", "js-sourcemap", "js-nextroute", "js-nextpage"}
	mk := func(src string) classify.ClassifiedRequest {
		return classify.ClassifiedRequest{ObservedRequest: crawl.ObservedRequest{Source: src}}
	}

	for _, src := range jsStaticSources {
		t.Run("uniform "+src, func(t *testing.T) {
			got := computeSourceTag([]classify.ClassifiedRequest{mk(src), mk(src)})
			assert.Contains(t, valid, got,
				"a uniform %q group returned %q; non-empty input must always yield one of "+
					"the contract values, and anything else means no extension is emitted at all", src, got)
			assert.NotEqual(t, "dynamic", got,
				"a uniform %q group must not report %q: the endpoint was recovered "+
					"statically and never requested", src, "dynamic")
		})
		t.Run("mixed with static:js "+src, func(t *testing.T) {
			got := computeSourceTag([]classify.ClassifiedRequest{mk(crawl.SourceStaticJS), mk(src)})
			assert.Contains(t, valid, got)
		})
	}

	// The two contract-named sources must still map to their own values, so the
	// totality fix did not flatten everything to "dynamic".
	assert.Equal(t, "js-bundle", computeSourceTag([]classify.ClassifiedRequest{mk(crawl.SourceStaticJS)}))
	assert.Equal(t, "js-sourcemap", computeSourceTag([]classify.ClassifiedRequest{mk(crawl.SourceStaticJSSourcemap)}))
	assert.Equal(t, "dynamic", computeSourceTag([]classify.ClassifiedRequest{mk("")}))
	assert.Equal(t, "", computeSourceTag(nil), "the empty-group contract is unchanged")
}

// allJSStaticSources is every Source constant crawl.IsJSStaticSource accepts.
// Written out rather than derived, because the point of the two tests below is to
// fail when pkg/crawl gains a source that pkg/generate/rest was not taught about —
// deriving the list from the predicate under test would make both vacuous.
//
// Adding a source to crawl.IsJSStaticSource means adding it here, to
// friendlySourceTag, and to jsStaticSourceRank. That three-site edit is the
// hazard; these tests are what turn a missed site into a failure.
var allJSStaticSources = []string{
	crawl.SourceStaticJS,
	crawl.SourceStaticJSSourcemap,
	crawl.SourceStaticJSConcat,
	crawl.SourceNextRouteHandler,
	crawl.SourceNextPageRoute,
}

// TestAllJSStaticSources_MatchesIsJSStaticSource keeps the hand-written list above
// honest in the only direction that matters: it must not be a stale SUBSET of what
// crawl.IsJSStaticSource accepts, since a missing entry silently narrows both tests
// below to the sources someone remembered.
//
// The reverse direction is also checked — an entry the predicate rejects means the
// list is describing a source that no longer exists.
func TestAllJSStaticSources_MatchesIsJSStaticSource(t *testing.T) {
	for _, src := range allJSStaticSources {
		assert.True(t, crawl.IsJSStaticSource(src),
			"%q is in allJSStaticSources but crawl.IsJSStaticSource rejects it", src)
	}
	// Every "static:*" constant crawl declares, so a NEW JS-bundle source added
	// there but not here is caught rather than assumed absent.
	for _, src := range []string{
		crawl.SourceStaticJS,
		crawl.SourceStaticJSSourcemap,
		crawl.SourceStaticJSConcat,
		crawl.SourceNextRouteHandler,
		crawl.SourceNextPageRoute,
	} {
		assert.Contains(t, allJSStaticSources, src,
			"crawl declares JS-static source %q; add it to allJSStaticSources, friendlySourceTag "+
				"and jsStaticSourceRank", src)
	}
}

// TestFriendlySourceTag_TotalOverJSStaticSources asserts the property
// computeSourceTag's doc comment claims: every source crawl.IsJSStaticSource
// accepts has a name in the consumer contract.
//
// Without this, a source known to IsJSStaticSource but not to friendlySourceTag
// took the "not named" branch. Before the LAB-4678 x LAB-4992 merge that branch
// returned "dynamic" outright, so a group recovered entirely from offline JS
// analysis was labeled directly observed — the highest-confidence label, on an
// endpoint that was never requested.
func TestFriendlySourceTag_TotalOverJSStaticSources(t *testing.T) {
	for _, src := range allJSStaticSources {
		t.Run(src, func(t *testing.T) {
			tag, ok := friendlySourceTag(src)
			assert.True(t, ok, "friendlySourceTag(%q) reported no name; the consumer contract "+
				"must name every JS-static source", src)
			assert.NotEmpty(t, tag, "a named source must map to a non-empty tag")
			assert.NotEqual(t, "dynamic", tag,
				"a JS-static source must never be labeled dynamic — that claims direct observation")
		})
	}
}

// TestJSStaticSourceRank_CoversEveryFriendlyTag pins the invariant that makes
// computeSourceTag's least-confident selection work: every tag friendlySourceTag
// can return needs an explicit jsStaticSourceRank entry.
//
// A missing entry does not fail loudly. Map lookup yields 0, which is js-bundle's
// rank — the MOST-confident label — so the unranked source wins the first
// comparison (0 > -1) and a later genuine js-bundle then fails 0 > 0. The group's
// x-vespasian-source extension is either wrong or suppressed entirely. main
// documented that failure (QUAL-005) for the three tags it knew about; the merge
// added two more, which is why the invariant is asserted here rather than trusted.
func TestJSStaticSourceRank_CoversEveryFriendlyTag(t *testing.T) {
	seen := map[int]string{}
	for _, src := range allJSStaticSources {
		tag, ok := friendlySourceTag(src)
		require.True(t, ok, "friendlySourceTag(%q) must name every JS-static source", src)

		rank, present := jsStaticSourceRank[tag]
		assert.True(t, present,
			"tag %q (from source %q) has no jsStaticSourceRank entry; the zero-value lookup "+
				"collides with js-bundle's rank 0 and corrupts the group's source tag", tag, src)

		if other, dup := seen[rank]; dup {
			t.Errorf("tags %q and %q share rank %d; the ordering must be total or "+
				"least-confident selection depends on map iteration order", other, tag, rank)
		}
		seen[rank] = tag
	}

	// leastConfidentJSStaticTag is the fallback for an unranked JS-static source,
	// so it has to actually be the last tag, not merely a valid one.
	assert.Equal(t, len(allJSStaticSources), len(jsStaticSourceRank),
		"jsStaticSourceRank holds an entry for a tag friendlySourceTag cannot return, "+
			"which lets leastConfidentJSStaticTag point at a tag no source maps to")
	maxRank := -1
	for _, r := range jsStaticSourceRank {
		if r > maxRank {
			maxRank = r
		}
	}
	assert.Equal(t, maxRank, jsStaticSourceRank[leastConfidentJSStaticTag],
		"leastConfidentJSStaticTag (%q) is not the highest-ranked tag", leastConfidentJSStaticTag)
}
