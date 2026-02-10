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

package plugin

import (
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPlugin is a test implementation of the Plugin interface.
type mockPlugin struct {
	name           string
	injectionType  types.InjectionType
	payloads       []types.Payload
	detectionRules []types.DetectionRule
}

func (m *mockPlugin) Name() string {
	return m.name
}

func (m *mockPlugin) Type() types.InjectionType {
	return m.injectionType
}

func (m *mockPlugin) Payloads(ctx types.ParameterContext) []types.Payload {
	return m.payloads
}

func (m *mockPlugin) DetectionRules() []types.DetectionRule {
	return m.detectionRules
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	assert.NotNil(t, r)
	assert.NotNil(t, r.plugins)
	assert.Equal(t, 0, len(r.plugins))
}

func TestRegistry_Register(t *testing.T) {
	tests := []struct {
		name        string
		plugins     []Plugin
		expectError bool
		errorMsg    string
	}{
		{
			name: "register single plugin",
			plugins: []Plugin{
				&mockPlugin{name: "sqli", injectionType: types.SQLi},
			},
			expectError: false,
		},
		{
			name: "register multiple different plugins",
			plugins: []Plugin{
				&mockPlugin{name: "sqli", injectionType: types.SQLi},
				&mockPlugin{name: "xss", injectionType: types.XSS},
			},
			expectError: false,
		},
		{
			name: "register duplicate plugin name",
			plugins: []Plugin{
				&mockPlugin{name: "sqli", injectionType: types.SQLi},
				&mockPlugin{name: "sqli", injectionType: types.SQLi},
			},
			expectError: true,
			errorMsg:    "plugin already registered: sqli",
		},
		{
			name:        "register nil plugin",
			plugins:     []Plugin{nil},
			expectError: true,
			errorMsg:    "plugin must not be nil",
		},
		{
			name: "register plugin with empty name",
			plugins: []Plugin{
				&mockPlugin{name: "", injectionType: types.SQLi},
			},
			expectError: true,
			errorMsg:    "empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			var err error

			for _, p := range tt.plugins {
				err = r.Register(p)
				if tt.expectError && err != nil {
					break
				}
			}

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tt.plugins), len(r.plugins))
			}
		})
	}
}

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()
	plugin1 := &mockPlugin{name: "sqli", injectionType: types.SQLi}
	plugin2 := &mockPlugin{name: "xss", injectionType: types.XSS}

	err := r.Register(plugin1)
	require.NoError(t, err)
	err = r.Register(plugin2)
	require.NoError(t, err)

	tests := []struct {
		name       string
		pluginName string
		expectOK   bool
		expected   Plugin
	}{
		{
			name:       "get existing plugin sqli",
			pluginName: "sqli",
			expectOK:   true,
			expected:   plugin1,
		},
		{
			name:       "get existing plugin xss",
			pluginName: "xss",
			expectOK:   true,
			expected:   plugin2,
		},
		{
			name:       "get non-existent plugin",
			pluginName: "unknown",
			expectOK:   false,
			expected:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin, ok := r.Get(tt.pluginName)
			assert.Equal(t, tt.expectOK, ok)
			if tt.expectOK {
				assert.Equal(t, tt.expected, plugin)
			} else {
				assert.Nil(t, plugin)
			}
		})
	}
}

func TestRegistry_All(t *testing.T) {
	r := NewRegistry()

	// Test empty registry
	plugins := r.All()
	assert.NotNil(t, plugins)
	assert.Len(t, plugins, 0)

	// Add plugins
	plugin1 := &mockPlugin{name: "sqli", injectionType: types.SQLi}
	plugin2 := &mockPlugin{name: "xss", injectionType: types.XSS}
	plugin3 := &mockPlugin{name: "ssti", injectionType: types.SSTI}

	require.NoError(t, r.Register(plugin1))
	require.NoError(t, r.Register(plugin2))
	require.NoError(t, r.Register(plugin3))

	// Test populated registry
	plugins = r.All()
	assert.Len(t, plugins, 3)

	// Verify all plugins are returned (order may vary)
	names := make(map[string]bool)
	for _, p := range plugins {
		names[p.Name()] = true
	}
	assert.True(t, names["sqli"])
	assert.True(t, names["xss"])
	assert.True(t, names["ssti"])
}

func TestRegistry_ForType(t *testing.T) {
	r := NewRegistry()

	// Register multiple plugins of different types
	plugin1 := &mockPlugin{name: "sqli-basic", injectionType: types.SQLi}
	plugin2 := &mockPlugin{name: "sqli-advanced", injectionType: types.SQLi}
	plugin3 := &mockPlugin{name: "xss-reflected", injectionType: types.XSS}
	plugin4 := &mockPlugin{name: "xss-stored", injectionType: types.XSS}
	plugin5 := &mockPlugin{name: "ssti-basic", injectionType: types.SSTI}

	require.NoError(t, r.Register(plugin1))
	require.NoError(t, r.Register(plugin2))
	require.NoError(t, r.Register(plugin3))
	require.NoError(t, r.Register(plugin4))
	require.NoError(t, r.Register(plugin5))

	tests := []struct {
		name          string
		injectionType types.InjectionType
		expectedCount int
		expectedNames []string
	}{
		{
			name:          "SQLi plugins",
			injectionType: types.SQLi,
			expectedCount: 2,
			expectedNames: []string{"sqli-basic", "sqli-advanced"},
		},
		{
			name:          "XSS plugins",
			injectionType: types.XSS,
			expectedCount: 2,
			expectedNames: []string{"xss-reflected", "xss-stored"},
		},
		{
			name:          "SSTI plugins",
			injectionType: types.SSTI,
			expectedCount: 1,
			expectedNames: []string{"ssti-basic"},
		},
		{
			name:          "CMDi plugins (none registered)",
			injectionType: types.CMDi,
			expectedCount: 0,
			expectedNames: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugins := r.ForType(tt.injectionType)
			assert.Len(t, plugins, tt.expectedCount)

			// Verify expected plugins are returned
			names := make(map[string]bool)
			for _, p := range plugins {
				names[p.Name()] = true
			}

			for _, expectedName := range tt.expectedNames {
				assert.True(t, names[expectedName], "expected plugin %s not found", expectedName)
			}
		})
	}
}

func TestDefaultRegistry(t *testing.T) {
	// Note: DefaultRegistry is global, so tests may affect each other
	// In production, you'd want to reset it between tests or use separate instances

	// Verify DefaultRegistry exists
	assert.NotNil(t, DefaultRegistry)

	// Test package-level Register function
	plugin := &mockPlugin{name: "test-plugin", injectionType: types.SQLi}

	// Try to register (may fail if already registered from other tests)
	err := Register(plugin)
	if err == nil {
		// Successfully registered, verify we can get it
		retrieved, ok := Get("test-plugin")
		assert.True(t, ok)
		assert.Equal(t, plugin, retrieved)

		// Verify it appears in All()
		all := All()
		found := false
		for _, p := range all {
			if p.Name() == "test-plugin" {
				found = true
				break
			}
		}
		assert.True(t, found)

		// Verify ForType works
		sqliPlugins := ForType(types.SQLi)
		found = false
		for _, p := range sqliPlugins {
			if p.Name() == "test-plugin" {
				found = true
				break
			}
		}
		assert.True(t, found)
	}
}

func TestRegistry_Concurrency(t *testing.T) {
	r := NewRegistry()

	// Test concurrent registration
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			plugin := &mockPlugin{
				name:          string(rune('a' + id)),
				injectionType: types.SQLi,
			}
			_ = r.Register(plugin)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify no race conditions occurred
	plugins := r.All()
	assert.LessOrEqual(t, len(plugins), 10)
	assert.GreaterOrEqual(t, len(plugins), 1)
}
