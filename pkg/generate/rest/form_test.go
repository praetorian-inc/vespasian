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
	"mime/multipart"
	"net/textproto"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseURLEncodedForm(t *testing.T) {
	t.Run("basic fields with type inference", func(t *testing.T) {
		body := []byte("name=Alice&age=30")
		schema := ParseURLEncodedForm(body)
		if schema == nil {
			t.Fatal("expected schema, got nil")
		}
		if schema.Value == nil || schema.Value.Properties == nil {
			t.Fatal("expected object schema with properties")
		}
		if _, ok := schema.Value.Properties["name"]; !ok {
			t.Error("expected property 'name'")
		}
		if _, ok := schema.Value.Properties["age"]; !ok {
			t.Error("expected property 'age'")
		}
		nameType := schema.Value.Properties["name"].Value.Type.Slice()[0]
		if nameType != "string" {
			t.Errorf("name type = %q, want string", nameType)
		}
		ageType := schema.Value.Properties["age"].Value.Type.Slice()[0]
		if ageType != "integer" {
			t.Errorf("age type = %q, want integer", ageType)
		}
	})

	t.Run("empty body returns nil", func(t *testing.T) {
		if schema := ParseURLEncodedForm([]byte("")); schema != nil {
			t.Error("expected nil for empty body")
		}
		if schema := ParseURLEncodedForm(nil); schema != nil {
			t.Error("expected nil for nil body")
		}
	})
}

func TestParseMultipartForm(t *testing.T) {
	t.Run("text field becomes string", func(t *testing.T) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		if err := w.WriteField("username", "alice"); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()

		schema := ParseMultipartForm(buf.Bytes(), w.Boundary())
		if schema == nil {
			t.Fatal("expected schema, got nil")
		}
		if _, ok := schema.Value.Properties["username"]; !ok {
			t.Error("expected property 'username'")
		}
		uType := schema.Value.Properties["username"].Value.Type.Slice()[0]
		if uType != "string" {
			t.Errorf("username type = %q, want string", uType)
		}
	})

	t.Run("file field becomes string/binary", func(t *testing.T) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="avatar"; filename="photo.jpg"`)
		h.Set("Content-Type", "image/jpeg")
		fw, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte("JPEG_DATA"))
		_ = w.Close()

		schema := ParseMultipartForm(buf.Bytes(), w.Boundary())
		if schema == nil {
			t.Fatal("expected schema, got nil")
		}
		prop, ok := schema.Value.Properties["avatar"]
		if !ok {
			t.Fatal("expected property 'avatar'")
		}
		if prop.Value.Type.Slice()[0] != "string" {
			t.Errorf("avatar type = %q, want string", prop.Value.Type.Slice()[0])
		}
		if prop.Value.Format != "binary" {
			t.Errorf("avatar format = %q, want binary", prop.Value.Format)
		}
	})

	t.Run("mixed text and file fields", func(t *testing.T) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		if err := w.WriteField("description", "hello world"); err != nil {
			t.Fatal(err)
		}
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="upload"; filename="data.bin"`)
		fw, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte("binary content"))
		_ = w.Close()

		schema := ParseMultipartForm(buf.Bytes(), w.Boundary())
		if schema == nil {
			t.Fatal("expected schema, got nil")
		}
		if _, ok := schema.Value.Properties["description"]; !ok {
			t.Error("expected property 'description'")
		}
		upload, ok := schema.Value.Properties["upload"]
		if !ok {
			t.Fatal("expected property 'upload'")
		}
		if upload.Value.Format != "binary" {
			t.Errorf("upload format = %q, want binary", upload.Value.Format)
		}
	})

	t.Run("empty boundary returns nil", func(t *testing.T) {
		if schema := ParseMultipartForm([]byte("data"), ""); schema != nil {
			t.Error("expected nil for empty boundary")
		}
	})
}

func TestMergeMultipartBodies(t *testing.T) {
	t.Run("merges properties from two observations", func(t *testing.T) {
		var buf1 bytes.Buffer
		w1 := multipart.NewWriter(&buf1)
		if err := w1.WriteField("username", "alice"); err != nil {
			t.Fatal(err)
		}
		_ = w1.Close()
		ct1 := "multipart/form-data; boundary=" + w1.Boundary()

		var buf2 bytes.Buffer
		w2 := multipart.NewWriter(&buf2)
		if err := w2.WriteField("email", "alice@example.com"); err != nil {
			t.Fatal(err)
		}
		_ = w2.Close()
		ct2 := "multipart/form-data; boundary=" + w2.Boundary()

		schema := mergeMultipartBodies(
			[][]byte{buf1.Bytes(), buf2.Bytes()},
			[]string{ct1, ct2},
		)
		if schema == nil {
			t.Fatal("expected merged schema, got nil")
		}
		if _, ok := schema.Value.Properties["username"]; !ok {
			t.Error("expected property 'username' from first observation")
		}
		if _, ok := schema.Value.Properties["email"]; !ok {
			t.Error("expected property 'email' from second observation")
		}
	})

	t.Run("single observation returns that observation's schema", func(t *testing.T) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		if err := w.WriteField("field1", "value1"); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		ct := "multipart/form-data; boundary=" + w.Boundary()

		schema := mergeMultipartBodies([][]byte{buf.Bytes()}, []string{ct})
		if schema == nil {
			t.Fatal("expected schema, got nil")
		}
		if _, ok := schema.Value.Properties["field1"]; !ok {
			t.Error("expected property 'field1'")
		}
	})

	t.Run("missing content-type entry skips that observation", func(t *testing.T) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		if err := w.WriteField("name", "bob"); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		// Provide body but no corresponding content-type entry.
		schema := mergeMultipartBodies([][]byte{buf.Bytes()}, []string{})
		// With no boundary the observation is skipped; result is nil.
		if schema != nil {
			t.Error("expected nil when no content-type provided")
		}
	})
}

func TestMergeObjectSchemas(t *testing.T) {
	t.Run("conflict on same property promotes to string", func(t *testing.T) {
		// base has "count" as integer, overlay has "count" as string — conflict.
		base := ParseURLEncodedForm([]byte("count=42"))
		overlay := ParseURLEncodedForm([]byte("count=hello"))
		if base == nil || overlay == nil {
			t.Fatal("test setup failed: expected non-nil schemas")
		}

		merged := mergeObjectSchemas(base, overlay)
		if merged == nil {
			t.Fatal("expected merged schema, got nil")
		}
		countProp, ok := merged.Value.Properties["count"]
		if !ok {
			t.Fatal("expected property 'count' in merged schema")
		}
		// After conflict, property should be promoted to string.
		gotType := countProp.Value.Type.Slice()[0]
		if gotType != "string" {
			t.Errorf("count type after conflict = %q, want string", gotType)
		}
	})

	t.Run("no conflict keeps original types", func(t *testing.T) {
		base := ParseURLEncodedForm([]byte("name=Alice&count=5"))
		overlay := ParseURLEncodedForm([]byte("active=true"))
		if base == nil || overlay == nil {
			t.Fatal("test setup failed: expected non-nil schemas")
		}

		merged := mergeObjectSchemas(base, overlay)
		if merged == nil {
			t.Fatal("expected merged schema, got nil")
		}
		if _, ok := merged.Value.Properties["active"]; !ok {
			t.Error("expected property 'active' from overlay")
		}
		// count was only in base; type should be unchanged.
		countProp, ok := merged.Value.Properties["count"]
		if !ok {
			t.Fatal("expected property 'count' in merged schema")
		}
		if countProp.Value.Type.Slice()[0] != "integer" {
			t.Errorf("count type = %q, want integer", countProp.Value.Type.Slice()[0])
		}
	})

	t.Run("nil base returns overlay", func(t *testing.T) {
		overlay := ParseURLEncodedForm([]byte("x=1"))
		result := mergeObjectSchemas(nil, overlay)
		if result != overlay {
			t.Error("expected overlay to be returned when base is nil")
		}
	})

	t.Run("nil overlay returns base", func(t *testing.T) {
		base := ParseURLEncodedForm([]byte("x=1"))
		result := mergeObjectSchemas(base, nil)
		if result != base {
			t.Error("expected base to be returned when overlay is nil")
		}
	})
}

func TestSchemaTypesConflict(t *testing.T) {
	t.Run("same types do not conflict", func(t *testing.T) {
		a := ParseURLEncodedForm([]byte("val=hello"))
		b := ParseURLEncodedForm([]byte("val=world"))
		if a == nil || b == nil {
			t.Fatal("test setup failed")
		}
		aProp := a.Value.Properties["val"]
		bProp := b.Value.Properties["val"]
		if schemaTypesConflict(aProp, bProp) {
			t.Error("string vs string should not conflict")
		}
	})

	t.Run("different types conflict", func(t *testing.T) {
		// "val=42" infers integer; "val=hello" infers string.
		aBase := ParseURLEncodedForm([]byte("val=42"))
		bBase := ParseURLEncodedForm([]byte("val=hello"))
		if aBase == nil || bBase == nil {
			t.Fatal("test setup failed")
		}
		aProp := aBase.Value.Properties["val"]
		bProp := bBase.Value.Properties["val"]
		if !schemaTypesConflict(aProp, bProp) {
			t.Error("integer vs string should conflict")
		}
	})

	t.Run("nil schema refs do not conflict", func(t *testing.T) {
		if schemaTypesConflict(nil, nil) {
			t.Error("nil vs nil should not conflict")
		}
	})
}

func TestParseURLEncodedForm_MalformedQuery(t *testing.T) {
	// %ZZ is an invalid percent-encoding sequence; url.ParseQuery returns an
	// error, so ParseURLEncodedForm must return nil (covers the err != nil
	// branch at form.go:50).
	schema := ParseURLEncodedForm([]byte("%ZZ=bad"))
	if schema != nil {
		t.Errorf("expected nil for malformed query string, got %+v", schema)
	}
}

func TestParseMultipartForm_AllPartsNameless(t *testing.T) {
	// Build a multipart body where the only part has no `name` attribute in
	// its Content-Disposition header. After the loop, Properties will be
	// empty, so ParseMultipartForm must return nil (covers the
	// len(schema.Properties) == 0 branch at form.go:94).
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	// Omit `name` so that part.FormName() returns "".
	h.Set("Content-Disposition", "form-data")
	h.Set("Content-Type", "text/plain")
	fw, err := w.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("some data"))
	_ = w.Close()

	schema := ParseMultipartForm(buf.Bytes(), w.Boundary())
	if schema != nil {
		t.Errorf("expected nil when all parts are nameless, got %+v", schema)
	}
}

func TestSchemaTypesConflict_NilValueType(t *testing.T) {
	// Both SchemaRefs have a non-nil Value but a nil Value.Type.
	// schemaTypesConflict should return false because the nil-Type guard
	// fires before any comparison.
	a := &openapi3.SchemaRef{Value: &openapi3.Schema{}}
	b := &openapi3.SchemaRef{Value: &openapi3.Schema{}}
	if schemaTypesConflict(a, b) {
		t.Error("expected false when both Value.Type are nil, got true")
	}
}

// ---------------------------------------------------------------------------
// Edge-case tests added for LAB-2106
// ---------------------------------------------------------------------------

// TestParseURLEncodedForm_RepeatedKeys verifies that when the same key appears
// multiple times in the query string (e.g. foo=1&foo=2&foo=3), the parser uses
// only the FIRST value to infer the property type. The current implementation
// reads vals[0], so repeated keys are NOT preserved as an array — only the
// first occurrence is considered. This is the documented current behavior.
func TestParseURLEncodedForm_RepeatedKeys(t *testing.T) {
	schema := ParseURLEncodedForm([]byte("foo=1&foo=2&foo=3"))
	require.NotNil(t, schema, "expected non-nil schema for repeated key")
	require.NotNil(t, schema.Value)
	require.NotNil(t, schema.Value.Properties)

	prop, ok := schema.Value.Properties["foo"]
	assert.True(t, ok, "expected property 'foo' to exist")
	require.NotNil(t, prop)
	require.NotNil(t, prop.Value)

	// "1" is parsed as integer by inferQueryParamType.
	// Current behavior: only vals[0] ("1") is examined — NOT an array.
	gotType := prop.Value.Type.Slice()[0]
	assert.Equal(t, "integer", gotType, "repeated key uses first value for type inference")
}

// TestParseURLEncodedForm_EmptyValues verifies that fields with empty string
// values ("username=&password=") produce string-typed properties. An empty
// string does not match integer, number, or boolean patterns, so it falls
// through to the "string" default in inferQueryParamType.
func TestParseURLEncodedForm_EmptyValues(t *testing.T) {
	schema := ParseURLEncodedForm([]byte("username=&password="))
	require.NotNil(t, schema, "expected non-nil schema for empty-value fields")
	require.NotNil(t, schema.Value)
	require.NotNil(t, schema.Value.Properties)

	for _, field := range []string{"username", "password"} {
		prop, ok := schema.Value.Properties[field]
		assert.True(t, ok, "expected property %q to exist", field)
		if ok {
			require.NotNil(t, prop.Value)
			gotType := prop.Value.Type.Slice()[0]
			assert.Equal(t, "string", gotType, "empty value for %q should yield string type", field)
		}
	}
}

// TestParseURLEncodedForm_SpecialChars verifies that percent-encoded characters
// (spaces as '+', colons as '%3A') do not cause the parser to choke. We only
// verify that the properties are present because the parser infers types from
// decoded values, not the raw encoded bytes, and the schema stores types, not
// the values themselves.
func TestParseURLEncodedForm_SpecialChars(t *testing.T) {
	// q=hello+world  → decoded value "hello world" → type string
	// filter=name%3Aalice → decoded value "name:alice" → type string
	schema := ParseURLEncodedForm([]byte("q=hello+world&filter=name%3Aalice"))
	require.NotNil(t, schema, "expected non-nil schema for percent-encoded input")
	require.NotNil(t, schema.Value)
	require.NotNil(t, schema.Value.Properties)

	assert.Contains(t, schema.Value.Properties, "q", "expected property 'q'")
	assert.Contains(t, schema.Value.Properties, "filter", "expected property 'filter'")
}

// TestParseMultipartForm_MultipleFilesSameName verifies behavior when two
// parts share the same name and both carry filenames ("files"). The current
// implementation iterates parts sequentially and writes to
// schema.Properties[name] each time, so the second part OVERWRITES the first.
// The result is a single "files" property with type string, format binary.
// This is the documented current behavior — the parser does NOT produce an
// array of files.
func TestParseMultipartForm_MultipleFilesSameName(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, fname := range []string{"a.jpg", "b.png"} {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="files"; filename="`+fname+`"`)
		h.Set("Content-Type", "image/jpeg")
		fw, err := w.CreatePart(h)
		require.NoError(t, err)
		_, _ = fw.Write([]byte("data"))
	}
	_ = w.Close()

	schema := ParseMultipartForm(buf.Bytes(), w.Boundary())
	require.NotNil(t, schema, "expected non-nil schema")
	require.NotNil(t, schema.Value)
	require.NotNil(t, schema.Value.Properties)

	prop, ok := schema.Value.Properties["files"]
	assert.True(t, ok, "expected property 'files' to exist")
	if ok {
		require.NotNil(t, prop.Value)
		assert.Equal(t, "string", prop.Value.Type.Slice()[0])
		// Current behavior: second file overwrites first; format is still binary.
		assert.Equal(t, "binary", prop.Value.Format)
	}
}

// TestParseMultipartForm_CharsetParameter verifies that extractBoundary handles
// a Content-Type with both a charset parameter and a boundary parameter, e.g.
// "multipart/form-data; charset=utf-8; boundary=X". The boundary "X" must be
// returned correctly regardless of parameter order.
func TestParseMultipartForm_CharsetParameter(t *testing.T) {
	ct := "multipart/form-data; charset=utf-8; boundary=X"
	boundary := extractBoundary(ct)
	assert.Equal(t, "X", boundary, "extractBoundary should return boundary even when charset is present")
}

// TestParseMultipartForm_NonASCIIFieldValue verifies that a text field whose
// value contains multi-byte UTF-8 characters (e.g. "日本語") is parsed
// correctly and produces a property with type string.
func TestParseMultipartForm_NonASCIIFieldValue(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	err := w.WriteField("lang", "日本語")
	require.NoError(t, err)
	_ = w.Close()

	schema := ParseMultipartForm(buf.Bytes(), w.Boundary())
	require.NotNil(t, schema, "expected non-nil schema for UTF-8 field value")
	require.NotNil(t, schema.Value)

	prop, ok := schema.Value.Properties["lang"]
	assert.True(t, ok, "expected property 'lang'")
	if ok {
		require.NotNil(t, prop.Value)
		assert.Equal(t, "string", prop.Value.Type.Slice()[0])
	}
}

// TestParseMultipartForm_Malformed_MissingClosingBoundary verifies behavior
// when the multipart body has parts but no closing boundary marker
// (--<boundary>--). Go's multipart.Reader stops at EOF after successfully
// reading any complete parts, so the current behavior is that already-parsed
// parts ARE returned (non-nil schema). This is the documented current behavior.
func TestParseMultipartForm_Malformed_MissingClosingBoundary(t *testing.T) {
	// Build a partial body: write a field but do NOT call w.Close(), which
	// would append the terminating "--<boundary>--" line.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	err := w.WriteField("partial", "value")
	require.NoError(t, err)
	// Intentionally omit w.Close() — no closing boundary.

	schema := ParseMultipartForm(buf.Bytes(), w.Boundary())
	// Current behavior: the part written before EOF is successfully parsed;
	// schema is non-nil and contains the "partial" property.
	require.NotNil(t, schema, "expected non-nil schema when closing boundary is missing but parts were read")
	require.NotNil(t, schema.Value)

	prop, ok := schema.Value.Properties["partial"]
	assert.True(t, ok, "expected property 'partial' to be parsed before EOF")
	if ok {
		require.NotNil(t, prop.Value)
		assert.Equal(t, "string", prop.Value.Type.Slice()[0])
	}
}

// BenchmarkParseURLEncodedForm and BenchmarkParseMultipartForm establish
// performance baselines for the form parsers introduced by LAB-2106.
// Useful as a reference before stretch-goal performance investigation.
func BenchmarkParseURLEncodedForm(b *testing.B) {
	body := []byte("username=alice&password=secret&age=30&admin=true&remember_me=false&note=hello+world")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseURLEncodedForm(body)
	}
}

func BenchmarkParseMultipartForm(b *testing.B) {
	// Construct a representative multipart body once
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("title", "benchmark doc")
	_ = w.WriteField("description", "performance baseline")
	hdr := make(textproto.MIMEHeader)
	hdr.Set("Content-Disposition", `form-data; name="file"; filename="test.bin"`)
	hdr.Set("Content-Type", "application/octet-stream")
	fw, _ := w.CreatePart(hdr)
	_, _ = fw.Write(make([]byte, 1024))
	_ = w.Close()
	body := buf.Bytes()
	boundary := w.Boundary()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseMultipartForm(body, boundary)
	}
}

// TestParseMultipartForm_EmptyFieldValue verifies that a text field with an
// empty value ("") is parsed as type string. An empty string does not match
// integer, number, or boolean, so inferQueryParamType returns "string".
func TestParseMultipartForm_EmptyFieldValue(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	err := w.WriteField("empty", "")
	require.NoError(t, err)
	_ = w.Close()

	schema := ParseMultipartForm(buf.Bytes(), w.Boundary())
	require.NotNil(t, schema, "expected non-nil schema for empty field value")
	require.NotNil(t, schema.Value)

	prop, ok := schema.Value.Properties["empty"]
	assert.True(t, ok, "expected property 'empty' to exist")
	if ok {
		require.NotNil(t, prop.Value)
		assert.Equal(t, "string", prop.Value.Type.Slice()[0])
	}
}

// TestParseMultipartForm_BinaryFile verifies that a file part containing
// binary content (PNG magic bytes) is parsed without mangling the body and
// produces a property with type string, format binary.
func TestParseMultipartForm_BinaryFile(t *testing.T) {
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="screenshot"; filename="img.png"`)
	h.Set("Content-Type", "image/png")
	fw, err := w.CreatePart(h)
	require.NoError(t, err)
	_, err = fw.Write(pngMagic)
	require.NoError(t, err)
	_ = w.Close()

	schema := ParseMultipartForm(buf.Bytes(), w.Boundary())
	require.NotNil(t, schema, "expected non-nil schema for binary file part")
	require.NotNil(t, schema.Value)

	prop, ok := schema.Value.Properties["screenshot"]
	assert.True(t, ok, "expected property 'screenshot'")
	if ok {
		require.NotNil(t, prop.Value)
		assert.Equal(t, "string", prop.Value.Type.Slice()[0])
		assert.Equal(t, "binary", prop.Value.Format, "file field should have format binary")
	}
}

// TestMergeURLEncodedBodies_DifferentFieldsPerObservation verifies that merging
// three observations with partially overlapping fields produces a schema with
// the union of all observed fields (a, b, c, d).
func TestMergeURLEncodedBodies_DifferentFieldsPerObservation(t *testing.T) {
	bodies := [][]byte{
		[]byte("a=1&b=2"),
		[]byte("b=2&c=3"),
		[]byte("a=1&d=4"),
	}
	schema := mergeURLEncodedBodies(bodies)
	require.NotNil(t, schema, "expected non-nil merged schema")
	require.NotNil(t, schema.Value)
	require.NotNil(t, schema.Value.Properties)

	for _, field := range []string{"a", "b", "c", "d"} {
		assert.Contains(t, schema.Value.Properties, field,
			"merged schema should contain property %q (union of all observations)", field)
	}
}

// TestMergeURLEncodedBodies_ConflictingTypes verifies that when the same field
// appears with different value types across observations (integer then string),
// the merged schema promotes the property type to string.
func TestMergeURLEncodedBodies_ConflictingTypes(t *testing.T) {
	bodies := [][]byte{
		[]byte("count=42"),    // "42" → integer
		[]byte("count=hello"), // "hello" → string
	}
	schema := mergeURLEncodedBodies(bodies)
	require.NotNil(t, schema, "expected non-nil merged schema")
	require.NotNil(t, schema.Value)
	require.NotNil(t, schema.Value.Properties)

	prop, ok := schema.Value.Properties["count"]
	assert.True(t, ok, "expected property 'count' in merged schema")
	if ok {
		require.NotNil(t, prop.Value)
		gotType := prop.Value.Type.Slice()[0]
		assert.Equal(t, "string", gotType,
			"conflicting types (integer vs string) should be promoted to string")
	}
}

func TestGetHeader_CaseInsensitiveFallback(t *testing.T) {
	// The map uses title-case "Content-Type" as the stored key.
	// Querying with lowercase "content-type" must fall through to the
	// scan loop and still return the value.
	headers := map[string]string{
		"Content-Type": "application/json",
	}
	got := getHeader(headers, "content-type")
	if got != "application/json" {
		t.Errorf("getHeader case-insensitive fallback: got %q, want %q", got, "application/json")
	}
}

func TestExtractBoundary(t *testing.T) {
	t.Run("valid content-type with boundary", func(t *testing.T) {
		ct := `multipart/form-data; boundary=----WebKitFormBoundaryABC123`
		boundary := extractBoundary(ct)
		if boundary != "----WebKitFormBoundaryABC123" {
			t.Errorf("boundary = %q, want ----WebKitFormBoundaryABC123", boundary)
		}
	})

	t.Run("no boundary returns empty string", func(t *testing.T) {
		if boundary := extractBoundary("application/json"); boundary != "" {
			t.Errorf("boundary = %q, want empty string", boundary)
		}
	})

	t.Run("malformed content-type returns empty string", func(t *testing.T) {
		if boundary := extractBoundary(""); boundary != "" {
			t.Errorf("boundary = %q, want empty string", boundary)
		}
	})
}
