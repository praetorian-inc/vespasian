// Package registry provides generic capability registration and discovery.
//
// This package implements the factory pattern for dynamic capability
// loading. Capabilities self-register via init() functions, enabling
// modular plugin-style architecture.
package registry

import (
	"fmt"
	"sort"
	"sync"
)

// Config holds configuration for capability instantiation.
type Config map[string]any

// ErrNotFound is returned when a capability is not registered.
var ErrNotFound = fmt.Errorf("capability not found")

// Registry manages registered capabilities of a specific type.
// It is safe for concurrent use.
type Registry[T any] struct {
	mu        sync.RWMutex
	factories map[string]func(Config) (T, error)
	name      string
}

// New creates a new registry with the given name.
func New[T any](name string) *Registry[T] {
	return &Registry[T]{
		factories: make(map[string]func(Config) (T, error)),
		name:      name,
	}
}

// Register adds a factory function for the given capability name.
// If a factory with the same name already exists, it is replaced.
func (r *Registry[T]) Register(name string, factory func(Config) (T, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[name] = factory
}

// Create instantiates a capability by name with the given config.
func (r *Registry[T]) Create(name string, cfg Config) (T, error) {
	r.mu.RLock()
	factory, ok := r.factories[name]
	r.mu.RUnlock()

	if !ok {
		var zero T
		return zero, fmt.Errorf("%w: %s in %s registry", ErrNotFound, name, r.name)
	}

	return factory(cfg)
}

// List returns all registered capability names, sorted alphabetically.
func (r *Registry[T]) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Has checks if a capability is registered.
func (r *Registry[T]) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.factories[name]
	return ok
}

// Count returns the number of registered capabilities.
func (r *Registry[T]) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.factories)
}

// Name returns the registry name.
func (r *Registry[T]) Name() string {
	return r.name
}
