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

package wsdl

import (
	"encoding/xml"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// T002: RED — value-based type inference tests.
func TestInferTypeFromValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
		name  string
	}{
		// Rule 3: empty / whitespace-only → "" (skip marker)
		{"", "", "empty string"},
		{"   ", "", "whitespace only"},
		{"\t\n", "", "tab newline"},

		// Rule 4: boolean (case-sensitive: only true/false)
		{"true", "xsd:boolean", "true"},
		{"false", "xsd:boolean", "false"},
		// These fall through to xsd:string (not canonical booleans)
		{"TRUE", "xsd:string", "TRUE not boolean"},
		{"False", "xsd:string", "False not boolean"},

		// Rule 5: integer (leading zeros excluded — likely identifiers/ZIP codes)
		{"42", "xsd:int", "positive integer"},
		{"-7", "xsd:int", "negative integer"},
		{"0", "xsd:int", "zero"},
		// Leading-zero strings fall through to xsd:string (ZIP codes, version
		// segments, padded IDs) — guards against misclassifying identifiers
		// that an xs:int parser would silently corrupt.
		{"0123", "xsd:string", "leading-zero ZIP-like falls to string"},
		{"02115", "xsd:string", "leading-zero numeric ZIP code"},
		{"-007", "xsd:string", "leading-zero negative falls to string"},
		{"1.2.3", "xsd:string", "version-like falls to string (multiple dots)"},

		// Rule 6: decimal
		{"3.14", "xsd:decimal", "positive decimal"},
		{"-0.5", "xsd:decimal", "negative decimal"},

		// Rule 7: date
		{"2026-05-25", "xsd:date", "ISO date"},

		// Rule 8: dateTime variants
		{"2026-05-25T10:30:00", "xsd:dateTime", "bare dateTime"},
		{"2026-05-25T10:30:00Z", "xsd:dateTime", "dateTime with Z"},
		{"2026-05-25T10:30:00+02:00", "xsd:dateTime", "dateTime with offset"},
		{"2026-05-25T10:30:00.123Z", "xsd:dateTime", "dateTime with fractional seconds"},

		// Rule 9: string fallback
		{"hello world", "xsd:string", "string fallback"},
		{"123abc", "xsd:string", "alphanumeric"},
		{"2026-13-99", "xsd:string", "invalid date falls to string"},
		// Calendar-impossible date/time values match the regex shape but are
		// not valid xs:date/xs:dateTime, so they must fall to xsd:string rather
		// than be mistyped (a consumer would reject them against the schema).
		{"2026-02-31", "xsd:string", "Feb 31 is not a real date"},
		{"2023-02-29", "xsd:string", "Feb 29 in a non-leap year"},
		{"2026-05-25T99:99:99", "xsd:string", "out-of-range clock fields"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferTypeFromValue(strings.TrimSpace(tt.input))
			assert.Equal(t, tt.want, got, "inferTypeFromValue(%q)", tt.input)
		})
	}
}

// T004: RED — extractSOAPParameters envelope detection tests.
func TestExtractSOAPParameters_EnvelopeDetection(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantNil bool
	}{
		{
			name: "SOAP 1.1 with soap: prefix",
			body: `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Ping/></soap:Body></soap:Envelope>`,
		},
		{
			name: "SOAP 1.1 with SOAP-ENV: prefix",
			body: `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><Ping/></SOAP-ENV:Body></SOAP-ENV:Envelope>`,
		},
		{
			name: "SOAP 1.2 with env: prefix",
			body: `<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Body><Ping/></env:Body></env:Envelope>`,
		},
		{
			name: "SOAP 1.2 default namespace",
			body: `<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body><Ping/></Body></Envelope>`,
		},
		{
			name:    "plain Body without envelope namespace → nil",
			body:    `<Envelope><Body><Ping/></Body></Envelope>`,
			wantNil: true,
		},
		{
			name:    "well-formed envelope with no Body → nil",
			body:    `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><Auth>x</Auth></soap:Header></soap:Envelope>`,
			wantNil: true,
		},
		{
			name:    "envelope with HTML-like body element (no SOAP ns) → nil",
			body:    `<html><body><div>nope</div></body></html>`,
			wantNil: true,
		},
		{
			name:    "empty body → nil",
			body:    ``,
			wantNil: true,
		},
		{
			name:    "malformed XML → nil (no panic)",
			body:    `<not valid xml`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSOAPParameters([]byte(tt.body))
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

// T006: RED — operation element + scalar parameter tests.
func TestExtractSOAPParameters_ScalarParams(t *testing.T) {
	t.Run("single scalar param with namespace", func(t *testing.T) {
		body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><tns:GetUserRequest xmlns:tns="http://localhost/soap"><id>1</id></tns:GetUserRequest></soap:Body></soap:Envelope>`
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		assert.Equal(t, []string{"id"}, result.OrderedKeys)
		require.Contains(t, result.Params, "id")
		assert.Equal(t, "xsd:int", result.Params["id"].XSDType)
		assert.Equal(t, "http://localhost/soap", result.Namespace)
	})

	t.Run("multiple scalars", func(t *testing.T) {
		body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Add><a>5</a><b>7</b></Add></soap:Body></soap:Envelope>`
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		assert.Equal(t, []string{"a", "b"}, result.OrderedKeys)
	})

	t.Run("empty operation element", func(t *testing.T) {
		body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Ping/></soap:Body></soap:Envelope>`
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		assert.Empty(t, result.OrderedKeys)
		assert.Empty(t, result.Params)
	})

	t.Run("mixed types", func(t *testing.T) {
		body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><X><n>3</n><flag>true</flag><name>alice</name></X></soap:Body></soap:Envelope>`
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		assert.Equal(t, "xsd:int", result.Params["n"].XSDType)
		assert.Equal(t, "xsd:boolean", result.Params["flag"].XSDType)
		assert.Equal(t, "xsd:string", result.Params["name"].XSDType)
	})
}

// T008: RED — nested complex-type tests.
func TestExtractSOAPParameters_NestedComplex(t *testing.T) {
	t.Run("one-deep nesting", func(t *testing.T) {
		body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><CreateUser><user><name>alice</name><age>30</age></user></CreateUser></soap:Body></soap:Envelope>`
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		require.Contains(t, result.Params, "user")
		assert.True(t, result.Params["user"].IsComplex)
		require.NotNil(t, result.Params["user"].Children)
		assert.Equal(t, []string{"name", "age"}, result.Params["user"].Children.OrderedKeys)
		assert.Equal(t, "xsd:string", result.Params["user"].Children.Params["name"].XSDType)
		assert.Equal(t, "xsd:int", result.Params["user"].Children.Params["age"].XSDType)
	})

	t.Run("two-deep nesting", func(t *testing.T) {
		body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><A><B><C><x>1</x></C></B></A></soap:Body></soap:Envelope>`
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		require.Contains(t, result.Params, "B")
		assert.True(t, result.Params["B"].IsComplex)
		require.NotNil(t, result.Params["B"].Children)
		require.Contains(t, result.Params["B"].Children.Params, "C")
		assert.True(t, result.Params["B"].Children.Params["C"].IsComplex)
	})

	// NT010: mixed text and children in same param: IsComplex wins, text is dropped.
	t.Run("mixed text and children promotes to complex", func(t *testing.T) {
		// The <user> element interleaves text ("noise") with a child element (<name>alice</name>).
		// walkParam collects text AND recurses into children; after the collect
		// loop, IsComplex=true wins and the scalar text is discarded (walkParam).
		body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
			`<soap:Body><Op><user>noise<name>alice</name></user></Op></soap:Body></soap:Envelope>`
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		require.Contains(t, result.Params, "user")
		user := result.Params["user"]
		assert.True(t, user.IsComplex, "user must be promoted to complex type")
		assert.Equal(t, "", user.XSDType, "XSDType must be empty for complex params")
		require.NotNil(t, user.Children)
		require.Contains(t, user.Children.Params, "name")
		assert.Equal(t, "xsd:string", user.Children.Params["name"].XSDType)
	})

	t.Run("depth cap retains the chain up to the bound and skips beyond it", func(t *testing.T) {
		// Build XML deeper than maxBodyDepth (= 32). The operation element
		// <Root> is depth 1; its direct child L0 is walked at depth 2, so Ln is
		// walked at depth n+2. walkParam stops recursing into children once its
		// own depth reaches maxBodyDepth, i.e. element at depth 32 (L30) skips
		// its children. Concretely: L0..L30 are recorded as a nested chain;
		// L31.. and the innermost <leaf> are discarded.
		var sb strings.Builder
		sb.WriteString(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Root>`)
		for i := 0; i < 35; i++ {
			fmt.Fprintf(&sb, "<L%d>", i)
		}
		sb.WriteString("<leaf>value</leaf>")
		for i := 34; i >= 0; i-- {
			fmt.Fprintf(&sb, "</L%d>", i)
		}
		sb.WriteString(`</Root></soap:Body></soap:Envelope>`)
		result := extractSOAPParameters([]byte(sb.String()))
		require.NotNil(t, result)

		// Walk the recorded chain L0 -> L1 -> ... and assert exactly where it
		// stops. lastDepth is the depth (n+2) of the deepest element walked.
		require.Equal(t, []string{"L0"}, result.OrderedKeys)
		node := result
		lastIdx := -1
		for i := 0; ; i++ {
			name := fmt.Sprintf("L%d", i)
			param, ok := node.Params[name]
			if !ok {
				break
			}
			lastIdx = i
			if param.Children == nil {
				break
			}
			node = param.Children
		}
		// L30 is the deepest retained element (walked at depth 32 = maxBodyDepth).
		assert.Equal(t, 30, lastIdx, "chain must retain exactly L0..L30")
		require.Contains(t, node.Params, "L30")
		assert.Nil(t, node.Params["L30"].Children,
			"L30 is at the depth cap, so its children must be skipped")
		assert.NotContains(t, node.Params, "L31", "elements beyond the cap must be skipped")
		assert.NotContains(t, node.Params, "leaf", "innermost element beyond the cap must be skipped")
	})
}

// T010: RED — xsi:type tests.
func TestExtractSOAPParameters_XSIType(t *testing.T) {
	const xsiDecl = `xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`
	const xsdDecl = `xmlns:xsd="http://www.w3.org/2001/XMLSchema"`
	const xsDecl = `xmlns:xs="http://www.w3.org/2001/XMLSchema"`

	t.Run("xsd:int via xsi:type", func(t *testing.T) {
		body := fmt.Sprintf(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Op %s %s><a xsi:type="xsd:int">5</a></Op></soap:Body></soap:Envelope>`, xsiDecl, xsdDecl)
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		require.Contains(t, result.Params, "a")
		assert.Equal(t, "xsd:int", result.Params["a"].XSDType)
	})

	t.Run("xs: prefix variant normalized to xsd:", func(t *testing.T) {
		body := fmt.Sprintf(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Op %s %s><a xsi:type="xs:boolean">true</a></Op></soap:Body></soap:Envelope>`, xsiDecl, xsDecl)
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		require.Contains(t, result.Params, "a")
		assert.Equal(t, "xsd:boolean", result.Params["a"].XSDType)
	})

	// Non-canonical xsi:type prefix (e.g. ns0:CustomType) falls back to
	// xsd:string instead of emitting a dangling tns:CustomType reference —
	// the generator does not synthesize matching <complexType> definitions.
	t.Run("unknown prefix falls back to xsd:string to avoid dangling reference", func(t *testing.T) {
		body := fmt.Sprintf(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Op %s><a xsi:type="ns0:CustomType">irrelevant</a></Op></soap:Body></soap:Envelope>`, xsiDecl)
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		require.Contains(t, result.Params, "a")
		assert.Equal(t, "xsd:string", result.Params["a"].XSDType,
			"non-canonical prefix must not emit tns:CustomType (no matching complexType in WSDL)")
	})

	t.Run("empty element with xsi:type is typed not skipped", func(t *testing.T) {
		body := fmt.Sprintf(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Op %s %s><a xsi:type="xsd:int"/></Op></soap:Body></soap:Envelope>`, xsiDecl, xsdDecl)
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		require.Contains(t, result.Params, "a")
		assert.Equal(t, "xsd:int", result.Params["a"].XSDType)
	})

	// NT009: xsi:type matched by URI even when a non-canonical prefix is used.
	// findXSIType matches by Name.Space == xsiNS, not by prefix.
	t.Run("non-canonical xsi prefix still matched by URI", func(t *testing.T) {
		// xmlns:foo is bound to the xsi URI; foo:type should be recognized as xsi:type.
		body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
			`<soap:Body>` +
			`<Op xmlns:foo="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">` +
			`<a foo:type="xsd:int">5</a>` +
			`</Op>` +
			`</soap:Body></soap:Envelope>`
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		require.Contains(t, result.Params, "a")
		assert.Equal(t, "xsd:int", result.Params["a"].XSDType,
			"type must be resolved by namespace URI, not by prefix string")
	})
}

// T012: RED — merge (aggregation / union) tests.
func TestSoapBodyInfo_Merge(t *testing.T) {
	t.Run("merge adds new params from B", func(t *testing.T) {
		a := &soapBodyInfo{
			OrderedKeys: []string{"id"},
			Params: map[string]*inferredParam{
				"id": {Name: "id", XSDType: "xsd:int"},
			},
		}
		b := &soapBodyInfo{
			OrderedKeys: []string{"id", "name"},
			Params: map[string]*inferredParam{
				"id":   {Name: "id", XSDType: "xsd:int"},
				"name": {Name: "name", XSDType: "xsd:string"},
			},
		}
		a.merge(b)
		assert.Equal(t, []string{"id", "name"}, a.OrderedKeys)
		require.Contains(t, a.Params, "name")
		assert.Equal(t, "xsd:string", a.Params["name"].XSDType)
	})

	t.Run("first-observed type wins on conflict", func(t *testing.T) {
		a := &soapBodyInfo{
			OrderedKeys: []string{"id"},
			Params: map[string]*inferredParam{
				"id": {Name: "id", XSDType: "xsd:int"},
			},
		}
		b := &soapBodyInfo{
			OrderedKeys: []string{"id"},
			Params: map[string]*inferredParam{
				"id": {Name: "id", XSDType: "xsd:string"},
			},
		}
		a.merge(b)
		// First-observed (xsd:int) wins
		assert.Equal(t, "xsd:int", a.Params["id"].XSDType)
	})

	t.Run("nested merge adds child params", func(t *testing.T) {
		aUser := &soapBodyInfo{
			OrderedKeys: []string{"name"},
			Params:      map[string]*inferredParam{"name": {Name: "name", XSDType: "xsd:string"}},
		}
		a := &soapBodyInfo{
			OrderedKeys: []string{"user"},
			Params: map[string]*inferredParam{
				"user": {Name: "user", IsComplex: true, Children: aUser},
			},
		}
		bUser := &soapBodyInfo{
			OrderedKeys: []string{"name", "age"},
			Params: map[string]*inferredParam{
				"name": {Name: "name", XSDType: "xsd:string"},
				"age":  {Name: "age", XSDType: "xsd:int"},
			},
		}
		b := &soapBodyInfo{
			OrderedKeys: []string{"user"},
			Params: map[string]*inferredParam{
				"user": {Name: "user", IsComplex: true, Children: bUser},
			},
		}
		a.merge(b)
		require.Contains(t, a.Params["user"].Children.Params, "age")
		assert.Equal(t, []string{"name", "age"}, a.Params["user"].Children.OrderedKeys)
	})

	t.Run("merge from empty A gains all B params", func(t *testing.T) {
		a := &soapBodyInfo{
			OrderedKeys: nil,
			Params:      map[string]*inferredParam{},
		}
		b := &soapBodyInfo{
			OrderedKeys: []string{"x", "y", "z"},
			Params: map[string]*inferredParam{
				"x": {Name: "x", XSDType: "xsd:int"},
				"y": {Name: "y", XSDType: "xsd:string"},
				"z": {Name: "z", XSDType: "xsd:boolean"},
			},
		}
		a.merge(b)
		assert.Equal(t, []string{"x", "y", "z"}, a.OrderedKeys)
		assert.Len(t, a.Params, 3)
	})

	// NT004: Namespace propagation from b to empty a.
	t.Run("Namespace propagates when a is empty and b is set", func(t *testing.T) {
		a := &soapBodyInfo{
			Namespace: "",
			Params:    map[string]*inferredParam{},
		}
		b := &soapBodyInfo{
			Namespace: "http://x/",
			Params:    map[string]*inferredParam{},
		}
		a.merge(b)
		assert.Equal(t, "http://x/", a.Namespace)
	})

	// NT011: merge does not overwrite an already-set Namespace; b empty leaves a empty.
	t.Run("Namespace is not overwritten and not propagated from empty b", func(t *testing.T) {
		t.Run("a already set is not overwritten by b", func(t *testing.T) {
			a := &soapBodyInfo{
				Namespace: "http://first/",
				Params:    map[string]*inferredParam{},
			}
			b := &soapBodyInfo{
				Namespace: "http://second/",
				Params:    map[string]*inferredParam{},
			}
			a.merge(b)
			assert.Equal(t, "http://first/", a.Namespace,
				"first-observed Namespace must not be overwritten")
		})

		t.Run("b empty leaves a empty", func(t *testing.T) {
			a := &soapBodyInfo{
				Namespace: "",
				Params:    map[string]*inferredParam{},
			}
			b := &soapBodyInfo{
				Namespace: "",
				Params:    map[string]*inferredParam{},
			}
			a.merge(b)
			assert.Equal(t, "", a.Namespace,
				"both empty: a's Namespace must remain empty")
		})
	})
}

// NT001: walkOperation truncated envelope returns partial info.
func TestWalkOperation_TruncatedEnvelopeReturnsPartial(t *testing.T) {
	// Build a SOAP envelope whose XML stream terminates inside the operation
	// element after one complete parameter (<a>1</a>) and after the opening
	// tag of a second parameter (<b>) whose content and close tag are missing.
	// The XML decoder emits StartElement "b" before hitting EOF, so walkParam
	// is invoked for "b" and it is registered with an empty XSDType (rule 3
	// skip marker). The partial-read path in walkOperation (the err != nil
	// return) returns the partially-collected info rather than nil — this is
	// the best-effort behavior the test pins.
	body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soap:Body><Op><a>1</a><b>`
	// truncated mid-element — no closing tags

	result := extractSOAPParameters([]byte(body))
	// Partial read path in walkOperation returns info, not nil.
	require.NotNil(t, result, "truncated envelope must return partial info, not nil")
	// "a" was fully parsed and must be present with its inferred type.
	require.Contains(t, result.Params, "a")
	assert.Equal(t, "xsd:int", result.Params["a"].XSDType)
	// "b"'s StartElement was emitted before EOF, so it appears in OrderedKeys
	// with an empty XSDType (the rule-3 skip marker for empty-text params).
	// This pins the actual best-effort behavior: both keys are present, "a"
	// is typed and "b" is untyped due to the truncation.
	require.Contains(t, result.Params, "b")
	assert.Equal(t, "", result.Params["b"].XSDType,
		"incomplete param b must have empty XSDType (rule-3 skip marker)")
	assert.False(t, result.Params["b"].IsComplex,
		"incomplete param b must not be flagged as complex")
}

// NT002: resolveXSIType direct unit test covering all branches including no-colon.
func TestResolveXSIType(t *testing.T) {
	tests := []struct {
		input string
		want  string
		name  string
	}{
		{"xsd:int", "xsd:int", "xsd prefix passthrough"},
		{"xs:boolean", "xsd:boolean", "xs prefix normalized to xsd"},
		// Non-canonical prefix → xsd:string (avoid dangling tns: reference;
		// see resolveXSIType doc comment in soapbody.go).
		{"ns0:Custom", "xsd:string", "non-canonical prefix falls back to xsd:string"},
		{"my:Foo", "xsd:string", "non-canonical prefix with short name"},
		{"boolean", "xsd:boolean", "no-colon prepends xsd"},
		{"", "xsd:string", "empty falls back to xsd:string"},
		// Whitespace handling: TrimSpace runs before parsing.
		{"   ", "xsd:string", "whitespace-only falls back to xsd:string"},
		{"  xsd:int  ", "xsd:int", "leading/trailing whitespace is trimmed"},
		{"\txs:boolean\n", "xsd:boolean", "tab/newline whitespace is trimmed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveXSIType(tt.input)
			assert.Equal(t, tt.want, got, "resolveXSIType(%q)", tt.input)
		})
	}
}

// NT003: isPlausibleDate covers the len != 10 defensive guard plus calendar
// validation — impossible day/month combinations and non-leap Feb 29 are
// rejected; a leap-year Feb 29 is accepted.
func TestIsPlausibleDate(t *testing.T) {
	tests := []struct {
		input string
		want  bool
		name  string
	}{
		{"2026-05-25", true, "valid date"},
		{"2026-13-25", false, "month > 12"},
		{"2026-05-32", false, "day > 31"},
		{"2026-00-15", false, "month = 00"},
		{"2026-05-00", false, "day = 00"},
		{"", false, "empty string len != 10"},
		{"2026-05-2", false, "len = 9"},
		{"2026-05-255", false, "len = 11"},
		// Calendar validity (regex shape is valid; the date is not).
		{"2026-02-31", false, "Feb 31 impossible"},
		{"2026-04-31", false, "Apr has 30 days"},
		{"2026-02-30", false, "Feb 30 impossible"},
		{"2023-02-29", false, "Feb 29 in non-leap year"},
		{"2024-02-29", true, "Feb 29 in leap year"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPlausibleDate(tt.input)
			assert.Equal(t, tt.want, got, "isPlausibleDate(%q)", tt.input)
		})
	}
}

// isPlausibleDateTime covers the valid dateTime shapes (bare, Z, numeric
// offset, fractional seconds) and rejects out-of-range clock fields that the
// datetimeRe \d{2} classes would otherwise accept.
func TestIsPlausibleDateTime(t *testing.T) {
	tests := []struct {
		input string
		want  bool
		name  string
	}{
		{"2026-05-25T10:30:00", true, "bare dateTime"},
		{"2026-05-25T10:30:00Z", true, "with Z"},
		{"2026-05-25T10:30:00+02:00", true, "with numeric offset"},
		{"2026-05-25T10:30:00.123Z", true, "fractional seconds with Z"},
		{"2026-05-25T10:30:00.123", true, "fractional seconds, no zone"},
		{"2026-05-25T99:99:99", false, "hour/min/sec out of range"},
		{"2026-05-25T24:00:00", false, "hour 24 out of range"},
		{"2026-13-25T10:30:00", false, "month 13 out of range"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPlausibleDateTime(tt.input)
			assert.Equal(t, tt.want, got, "isPlausibleDateTime(%q)", tt.input)
		})
	}
}

// T014: RED — inferTypesFromObservations tests.
func TestInferTypesFromObservations(t *testing.T) {
	t.Run("single operation with scalar params", func(t *testing.T) {
		obs := map[string]*soapBodyInfo{
			"GetUser": {
				Namespace:   "http://localhost/soap",
				OrderedKeys: []string{"id"},
				Params:      map[string]*inferredParam{"id": {Name: "id", XSDType: "xsd:int"}},
			},
		}
		ops := []string{"GetUser"}
		types := inferTypesFromObservations(ops, obs, "http://localhost/")
		require.NotNil(t, types)
		require.Len(t, types.Schemas, 1)
		assert.Equal(t, "http://localhost/", types.Schemas[0].TargetNS)
		require.Len(t, types.Schemas[0].Elements, 1)
		el := types.Schemas[0].Elements[0]
		assert.Equal(t, "GetUser", el.Name)
		require.NotNil(t, el.ComplexType)
		require.Len(t, el.ComplexType.Sequence, 1)
		assert.Equal(t, "id", el.ComplexType.Sequence[0].Name)
		assert.Equal(t, "xsd:int", el.ComplexType.Sequence[0].Type)
	})

	t.Run("two operations", func(t *testing.T) {
		obs := map[string]*soapBodyInfo{
			"GetUser":   {OrderedKeys: []string{"id"}, Params: map[string]*inferredParam{"id": {XSDType: "xsd:int"}}},
			"ListUsers": {OrderedKeys: []string{"filter"}, Params: map[string]*inferredParam{"filter": {XSDType: "xsd:string"}}},
		}
		ops := []string{"GetUser", "ListUsers"}
		types := inferTypesFromObservations(ops, obs, "http://localhost/")
		require.NotNil(t, types)
		require.Len(t, types.Schemas[0].Elements, 2)
		assert.Equal(t, "GetUser", types.Schemas[0].Elements[0].Name)
		assert.Equal(t, "ListUsers", types.Schemas[0].Elements[1].Name)
	})

	t.Run("nested complex param", func(t *testing.T) {
		childInfo := &soapBodyInfo{
			OrderedKeys: []string{"name", "age"},
			Params: map[string]*inferredParam{
				"name": {Name: "name", XSDType: "xsd:string"},
				"age":  {Name: "age", XSDType: "xsd:int"},
			},
		}
		obs := map[string]*soapBodyInfo{
			"CreateUser": {
				OrderedKeys: []string{"user"},
				Params: map[string]*inferredParam{
					"user": {Name: "user", IsComplex: true, Children: childInfo},
				},
			},
		}
		ops := []string{"CreateUser"}
		types := inferTypesFromObservations(ops, obs, "http://localhost/")
		require.NotNil(t, types)
		el := types.Schemas[0].Elements[0]
		require.Len(t, el.ComplexType.Sequence, 1)
		userEl := el.ComplexType.Sequence[0]
		assert.Equal(t, "user", userEl.Name)
		require.NotNil(t, userEl.ComplexType)
		assert.Len(t, userEl.ComplexType.Sequence, 2)

		// Smoke-check: must produce valid XML
		_, err := xml.MarshalIndent(types, "", "  ")
		assert.NoError(t, err)
	})

	t.Run("empty observations returns nil", func(t *testing.T) {
		types := inferTypesFromObservations(nil, map[string]*soapBodyInfo{}, "http://localhost/")
		assert.Nil(t, types)
	})

	// NT005a: all operations missing from observations — observations non-empty
	// but no op in the operations slice exists in the map → elements stays empty
	// → second nil-return path in inferTypesFromObservations (len(elements) == 0).
	t.Run("all operations missing from observations returns nil", func(t *testing.T) {
		// observations has an entry, but it is not referenced by operations.
		obs := map[string]*soapBodyInfo{
			"OtherOp": {OrderedKeys: []string{"x"}, Params: map[string]*inferredParam{"x": {XSDType: "xsd:int"}}},
		}
		ops := []string{"GetUser", "ListUsers"} // neither is in obs
		types := inferTypesFromObservations(ops, obs, "http://localhost/")
		assert.Nil(t, types,
			"all operations absent from observations → elements empty → nil return")
	})

	// NT005: operations not present in observations are silently skipped.
	t.Run("operations not in observations are silently skipped", func(t *testing.T) {
		obs := map[string]*soapBodyInfo{
			"GetUser":   {OrderedKeys: []string{"id"}, Params: map[string]*inferredParam{"id": {XSDType: "xsd:int"}}},
			"ListUsers": {OrderedKeys: []string{"filter"}, Params: map[string]*inferredParam{"filter": {XSDType: "xsd:string"}}},
		}
		// MissingOp is in operations slice but not in observations map.
		ops := []string{"GetUser", "MissingOp", "ListUsers"}
		types := inferTypesFromObservations(ops, obs, "http://localhost/")
		require.NotNil(t, types)
		require.Len(t, types.Schemas[0].Elements, 2, "MissingOp should be silently skipped")
		assert.Equal(t, "GetUser", types.Schemas[0].Elements[0].Name)
		assert.Equal(t, "ListUsers", types.Schemas[0].Elements[1].Name)
		for _, el := range types.Schemas[0].Elements {
			assert.NotEqual(t, "MissingOp", el.Name, "MissingOp must not appear in output")
		}
	})

	// NT006: all-skipped params (empty XSDType, not complex) yields ComplexType with nil Sequence.
	t.Run("all-skipped params yields empty complex type", func(t *testing.T) {
		// Parameters with XSDType=="" and IsComplex==false trigger the skip in buildComplexType.
		// This simulates e.g. <flag></flag> elements where text is empty.
		obs := map[string]*soapBodyInfo{
			"Ping": {
				OrderedKeys: []string{"flag", "note"},
				Params: map[string]*inferredParam{
					"flag": {Name: "flag", XSDType: "", IsComplex: false},
					"note": {Name: "note", XSDType: "", IsComplex: false},
				},
			},
		}
		ops := []string{"Ping"}
		types := inferTypesFromObservations(ops, obs, "http://localhost/")
		require.NotNil(t, types, "result must be non-nil even when all params are skipped")
		require.Len(t, types.Schemas[0].Elements, 1)
		el := types.Schemas[0].Elements[0]
		assert.Equal(t, "Ping", el.Name)
		require.NotNil(t, el.ComplexType)
		assert.Empty(t, el.ComplexType.Sequence, "all-skipped params yields empty sequence")
	})
}

// QUAL-002 fix: same-name sibling with mixed type info — first-typed-wins.
// For SOAP arrays / repeated elements, an empty observation must not
// overwrite a typed earlier one.
func TestWalkOperation_FirstTypedSiblingWins(t *testing.T) {
	t.Run("typed then empty: typed wins", func(t *testing.T) {
		body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
			`<soap:Body><Op><item>42</item><item></item></Op></soap:Body></soap:Envelope>`
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		require.Contains(t, result.Params, "item")
		assert.Equal(t, "xsd:int", result.Params["item"].XSDType,
			"first observation with a real value must not be overwritten by an empty sibling")
	})

	t.Run("empty then typed: typed upgrades", func(t *testing.T) {
		body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
			`<soap:Body><Op><item></item><item>42</item></Op></soap:Body></soap:Envelope>`
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		require.Contains(t, result.Params, "item")
		assert.Equal(t, "xsd:int", result.Params["item"].XSDType,
			"empty first observation must be upgraded by a later typed sibling")
	})

	t.Run("typed then typed: first wins", func(t *testing.T) {
		body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
			`<soap:Body><Op><item>42</item><item>hello</item></Op></soap:Body></soap:Envelope>`
		result := extractSOAPParameters([]byte(body))
		require.NotNil(t, result)
		assert.Equal(t, "xsd:int", result.Params["item"].XSDType,
			"first-typed-wins: later observation with different type must not overwrite")
	})
}

// QUAL-002 fix mirror for walkParam's children loop — same rule applies
// to repeated children inside a complex parameter.
func TestWalkParam_FirstTypedChildWins(t *testing.T) {
	body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soap:Body><Op><wrapper><value>3.14</value><value></value></wrapper></Op></soap:Body></soap:Envelope>`
	result := extractSOAPParameters([]byte(body))
	require.NotNil(t, result)
	require.Contains(t, result.Params, "wrapper")
	require.True(t, result.Params["wrapper"].IsComplex)
	require.NotNil(t, result.Params["wrapper"].Children)
	require.Contains(t, result.Params["wrapper"].Children.Params, "value")
	assert.Equal(t, "xsd:decimal", result.Params["wrapper"].Children.Params["value"].XSDType,
		"nested same-name sibling: first-typed-wins")
}

// QUAL-002 upgrade direction for walkParam's children loop: an empty first
// observation of a nested same-name child must be upgraded by a later typed
// sibling. Mirrors the walkOperation-level "empty then typed" case and covers
// the same-name-sibling upgrade branch inside walkParam's children loop.
func TestWalkParam_EmptyThenTypedChildUpgrades(t *testing.T) {
	body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soap:Body><Op><wrapper><value></value><value>3.14</value></wrapper></Op></soap:Body></soap:Envelope>`
	result := extractSOAPParameters([]byte(body))
	require.NotNil(t, result)
	require.Contains(t, result.Params, "wrapper")
	require.True(t, result.Params["wrapper"].IsComplex)
	require.NotNil(t, result.Params["wrapper"].Children)
	require.Contains(t, result.Params["wrapper"].Children.Params, "value")
	assert.Equal(t, "xsd:decimal", result.Params["wrapper"].Children.Params["value"].XSDType,
		"nested same-name sibling: empty first observation must be upgraded by a later typed sibling")
}

// QUAL-003 fix: merge upgrades an empty-typed parameter when a later
// observation has type info.
func TestSoapBodyInfo_Merge_UpgradesEmptyType(t *testing.T) {
	a := &soapBodyInfo{
		OrderedKeys: []string{"status"},
		Params:      map[string]*inferredParam{"status": {Name: "status", XSDType: ""}},
	}
	b := &soapBodyInfo{
		OrderedKeys: []string{"status"},
		Params:      map[string]*inferredParam{"status": {Name: "status", XSDType: "xsd:string"}},
	}
	a.merge(b)
	assert.Equal(t, "xsd:string", a.Params["status"].XSDType,
		"merge must upgrade an empty XSDType from a later observation that has type info")
}

// QUAL-003 negative: merge must NOT downgrade a typed parameter when a
// later observation is empty.
func TestSoapBodyInfo_Merge_DoesNotDowngradeTypedParam(t *testing.T) {
	a := &soapBodyInfo{
		OrderedKeys: []string{"status"},
		Params:      map[string]*inferredParam{"status": {Name: "status", XSDType: "xsd:int"}},
	}
	b := &soapBodyInfo{
		OrderedKeys: []string{"status"},
		Params:      map[string]*inferredParam{"status": {Name: "status", XSDType: ""}},
	}
	a.merge(b)
	assert.Equal(t, "xsd:int", a.Params["status"].XSDType,
		"merge must not downgrade a typed param with an empty later observation")
}

// QUAL-003 upgrade-to-complex: a scalar-but-empty first observation can be
// upgraded to a complex type by a later observation.
func TestSoapBodyInfo_Merge_UpgradesEmptyToComplex(t *testing.T) {
	a := &soapBodyInfo{
		OrderedKeys: []string{"data"},
		Params:      map[string]*inferredParam{"data": {Name: "data", XSDType: ""}},
	}
	b := &soapBodyInfo{
		OrderedKeys: []string{"data"},
		Params: map[string]*inferredParam{
			"data": {
				Name: "data", IsComplex: true,
				Children: &soapBodyInfo{
					OrderedKeys: []string{"id"},
					Params:      map[string]*inferredParam{"id": {Name: "id", XSDType: "xsd:int"}},
				},
			},
		},
	}
	a.merge(b)
	assert.True(t, a.Params["data"].IsComplex, "empty scalar must be upgradable to complex")
	require.NotNil(t, a.Params["data"].Children)
	assert.Equal(t, "xsd:int", a.Params["data"].Children.Params["id"].XSDType)
}

// hasType() unit tests — pin the predicate behavior used by the three
// upgrade gates above.
func TestInferredParam_HasType(t *testing.T) {
	tests := []struct {
		name string
		p    *inferredParam
		want bool
	}{
		{"empty leaf has no type", &inferredParam{}, false},
		{"typed leaf has type", &inferredParam{XSDType: "xsd:int"}, true},
		{"complex without children has type", &inferredParam{IsComplex: true}, true},
		{"complex with children has type", &inferredParam{IsComplex: true, Children: &soapBodyInfo{}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.p.hasType())
		})
	}
}

// shouldUpgradeWith() pins the first-with-type-wins predicate that
// centralizes the upgrade rule used by walkOperation, walkParam, and merge.
func TestInferredParam_ShouldUpgradeWith(t *testing.T) {
	typed := &inferredParam{XSDType: "xsd:int"}
	empty := &inferredParam{}
	complex := &inferredParam{IsComplex: true}
	otherTyped := &inferredParam{XSDType: "xsd:string"}

	tests := []struct {
		name      string
		existing  *inferredParam
		candidate *inferredParam
		want      bool
	}{
		{"empty upgraded by typed", empty, typed, true},
		{"empty upgraded by complex", empty, complex, true},
		{"typed not downgraded by empty", typed, empty, false},
		{"typed not replaced by other typed (first wins)", typed, otherTyped, false},
		{"complex not replaced by typed", complex, typed, false},
		{"empty stays empty when candidate is empty", empty, empty, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.existing.shouldUpgradeWith(tt.candidate))
		})
	}
}
