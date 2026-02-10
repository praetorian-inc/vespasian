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
	"fmt"
	"sync"

	"github.com/praetorian-inc/vespasian/pkg/types"
)

// Plugin defines an injection vulnerability class.
type Plugin interface {
	Name() string
	Type() types.InjectionType
	Payloads(ctx types.ParameterContext) []types.Payload
	DetectionRules() []types.DetectionRule
}

// Registry stores and manages registered plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Plugin
}

// NewRegistry creates a new plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
	}
}

// Register adds a plugin to the registry.
// Returns an error if a plugin with the same name is already registered.
func (r *Registry) Register(p Plugin) error {
	if p == nil {
		return fmt.Errorf("plugin must not be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	name := p.Name()
	if name == "" {
		return fmt.Errorf("plugin name must not be empty")
	}
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin already registered: %s", name)
	}

	r.plugins[name] = p
	return nil
}

// Get retrieves a plugin by name.
// Returns the plugin and true if found, nil and false otherwise.
func (r *Registry) Get(name string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugin, ok := r.plugins[name]
	return plugin, ok
}

// All returns all registered plugins.
func (r *Registry) All() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		result = append(result, p)
	}
	return result
}

// ForType returns all plugins that handle the given injection type.
func (r *Registry) ForType(t types.InjectionType) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Plugin
	for _, p := range r.plugins {
		if p.Type() == t {
			result = append(result, p)
		}
	}
	return result
}

// DefaultRegistry is the global plugin registry.
var DefaultRegistry = NewRegistry()

// Register adds a plugin to the default registry.
func Register(p Plugin) error {
	return DefaultRegistry.Register(p)
}

// Get retrieves a plugin from the default registry.
func Get(name string) (Plugin, bool) {
	return DefaultRegistry.Get(name)
}

// All returns all plugins from the default registry.
func All() []Plugin {
	return DefaultRegistry.All()
}

// ForType returns plugins for the given type from the default registry.
func ForType(t types.InjectionType) []Plugin {
	return DefaultRegistry.ForType(t)
}
