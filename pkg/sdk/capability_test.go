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

package sdk_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"

	"github.com/praetorian-inc/vespasian/pkg/sdk"
)

// TestCapability_CompileTimeCheck verifies the compile-time interface satisfaction.
var _ capability.Capability[capmodel.WebApplication] = (*sdk.Capability)(nil)

func TestCapability_Metadata(t *testing.T) {
	c := &sdk.Capability{}

	assert.Equal(t, "vespasian", c.Name())
	assert.Equal(t, "Discovers API endpoints via headless browser crawling and generates API specifications (OpenAPI 3.0, GraphQL SDL, WSDL)", c.Description())
	assert.Equal(t, capmodel.WebApplication{}, c.Input())
}

func TestCapability_Parameters(t *testing.T) {
	c := &sdk.Capability{}
	params := c.Parameters()

	require.Len(t, params, 11)

	byName := make(map[string]capability.Parameter, len(params))
	for _, p := range params {
		byName[p.Name] = p
	}

	t.Run("api_type", func(t *testing.T) {
		p, ok := byName["api_type"]
		require.True(t, ok)
		assert.Equal(t, "string", p.Type)
		assert.Equal(t, "auto", p.Default)
		assert.ElementsMatch(t, []string{"auto", "rest", "wsdl", "graphql"}, p.Options)
	})

	t.Run("depth", func(t *testing.T) {
		p, ok := byName["depth"]
		require.True(t, ok)
		assert.Equal(t, "int", p.Type)
		assert.Equal(t, "3", p.Default)
	})

	t.Run("max_pages", func(t *testing.T) {
		p, ok := byName["max_pages"]
		require.True(t, ok)
		assert.Equal(t, "int", p.Type)
		assert.Equal(t, "100", p.Default)
	})

	t.Run("timeout", func(t *testing.T) {
		p, ok := byName["timeout"]
		require.True(t, ok)
		assert.Equal(t, "int", p.Type)
		assert.Equal(t, "600", p.Default)
	})

	t.Run("confidence", func(t *testing.T) {
		p, ok := byName["confidence"]
		require.True(t, ok)
		assert.Equal(t, "float", p.Type)
		assert.Equal(t, "0.5", p.Default)
	})

	t.Run("headless", func(t *testing.T) {
		p, ok := byName["headless"]
		require.True(t, ok)
		assert.Equal(t, "bool", p.Type)
		assert.Equal(t, "true", p.Default)
	})

	t.Run("probe", func(t *testing.T) {
		p, ok := byName["probe"]
		require.True(t, ok)
		assert.Equal(t, "bool", p.Type)
		assert.Equal(t, "true", p.Default)
	})

	t.Run("scope", func(t *testing.T) {
		p, ok := byName["scope"]
		require.True(t, ok)
		assert.Equal(t, "string", p.Type)
		assert.Equal(t, "same-origin", p.Default)
		assert.ElementsMatch(t, []string{"same-origin", "same-domain"}, p.Options)
	})

	t.Run("headers", func(t *testing.T) {
		p, ok := byName["headers"]
		require.True(t, ok)
		assert.Equal(t, "string", p.Type)
		assert.Equal(t, "", p.Default)
	})

	t.Run("proxy", func(t *testing.T) {
		p, ok := byName["proxy"]
		require.True(t, ok)
		assert.Equal(t, "string", p.Type)
		assert.Equal(t, "", p.Default)
	})

	t.Run("deduplicate", func(t *testing.T) {
		p, ok := byName["deduplicate"]
		require.True(t, ok)
		assert.Equal(t, "bool", p.Type)
		assert.Equal(t, "true", p.Default)
	})
}

func TestCapability_Match_Valid(t *testing.T) {
	c := &sdk.Capability{}
	ctx := capability.ExecutionContext{}

	tests := []struct {
		name string
		url  string
	}{
		{"http URL", "http://example.com"},
		{"https URL", "https://example.com/api"},
		{"https with port", "https://example.com:8443/v1"},
		{"http with path", "http://localhost:8080/api/v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := capmodel.WebApplication{PrimaryURL: tt.url}
			err := c.Match(ctx, input)
			assert.NoError(t, err)
		})
	}
}

func TestCapability_Match_EmptyURL(t *testing.T) {
	c := &sdk.Capability{}
	ctx := capability.ExecutionContext{}

	input := capmodel.WebApplication{PrimaryURL: ""}
	err := c.Match(ctx, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "primary_url")
}

func TestCapability_Match_InvalidURL(t *testing.T) {
	c := &sdk.Capability{}
	ctx := capability.ExecutionContext{}

	tests := []struct {
		name string
		url  string
	}{
		// url.Parse succeeds for "not-a-url" (parsed as a relative path),
		// so the error comes from the scheme check, not the parse step.
		{"no scheme no host", "not-a-url"},
		{"path only", "/api/v1"},
		{"empty host with scheme", "http://"},
		// u.Host is ":443" (non-empty) pre-fix, but u.Hostname() returns ""
		// (strips the port), so the post-fix Hostname() check correctly rejects it.
		{"port-only host", "http://:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := capmodel.WebApplication{PrimaryURL: tt.url}
			err := c.Match(ctx, input)
			require.Error(t, err)
		})
	}
}

func TestCapability_Match_BadScheme(t *testing.T) {
	c := &sdk.Capability{}
	ctx := capability.ExecutionContext{}

	tests := []struct {
		name string
		url  string
	}{
		{"ftp scheme", "ftp://example.com"},
		{"file scheme", "file:///etc/passwd"},
		{"ws scheme", "ws://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := capmodel.WebApplication{PrimaryURL: tt.url}
			err := c.Match(ctx, input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "scheme")
		})
	}
}

// TestCapability_Invoke_RejectsInvalidScope verifies that scope validation runs
// before any browser launch or crawl work. The scope check at capability.go:191-193
// must fire immediately, making this test complete in well under 100 ms.
func TestCapability_Invoke_RejectsInvalidScope(t *testing.T) {
	c := &sdk.Capability{}
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "scope", Value: "not-a-scope"},
			{Name: "headless", Value: "false"}, // belt-and-suspenders: avoid browser path if scope check ever moves
		},
	}
	input := capmodel.WebApplication{PrimaryURL: "http://example.com"}

	// A nil emitter is fine because Emit is never reached when scope is invalid.
	err := c.Invoke(ctx, input, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid scope")
	assert.Contains(t, err.Error(), "not-a-scope")
}
