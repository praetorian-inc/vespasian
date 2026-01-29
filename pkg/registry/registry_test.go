package registry_test

import (
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProbe is a test implementation
type TestProbe struct {
	name string
}

func (p *TestProbe) Name() string {
	return p.name
}

func TestRegistry_Register(t *testing.T) {
	r := registry.New[*TestProbe]("test")

	// Register a probe factory
	r.Register("test-probe", func(cfg registry.Config) (*TestProbe, error) {
		return &TestProbe{name: "test-probe"}, nil
	})

	// Verify it was registered
	assert.True(t, r.Has("test-probe"))
}

func TestRegistry_Create(t *testing.T) {
	r := registry.New[*TestProbe]("test")

	r.Register("test-probe", func(cfg registry.Config) (*TestProbe, error) {
		return &TestProbe{name: "test-probe"}, nil
	})

	// Create instance
	probe, err := r.Create("test-probe", registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "test-probe", probe.Name())
}

func TestRegistry_Create_NotFound(t *testing.T) {
	r := registry.New[*TestProbe]("test")

	// Try to create non-existent probe
	_, err := r.Create("nonexistent", registry.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRegistry_List(t *testing.T) {
	r := registry.New[*TestProbe]("test")

	r.Register("probe-b", func(cfg registry.Config) (*TestProbe, error) {
		return &TestProbe{name: "probe-b"}, nil
	})
	r.Register("probe-a", func(cfg registry.Config) (*TestProbe, error) {
		return &TestProbe{name: "probe-a"}, nil
	})
	r.Register("probe-c", func(cfg registry.Config) (*TestProbe, error) {
		return &TestProbe{name: "probe-c"}, nil
	})

	// List should return sorted names
	names := r.List()
	expected := []string{"probe-a", "probe-b", "probe-c"}
	assert.Equal(t, expected, names)
}

func TestRegistry_Has(t *testing.T) {
	r := registry.New[*TestProbe]("test")

	r.Register("exists", func(cfg registry.Config) (*TestProbe, error) {
		return &TestProbe{name: "exists"}, nil
	})

	assert.True(t, r.Has("exists"))
	assert.False(t, r.Has("nonexistent"))
}

func TestRegistry_Count(t *testing.T) {
	r := registry.New[*TestProbe]("test")

	assert.Equal(t, 0, r.Count())

	r.Register("probe-1", func(cfg registry.Config) (*TestProbe, error) {
		return &TestProbe{name: "probe-1"}, nil
	})

	assert.Equal(t, 1, r.Count())

	r.Register("probe-2", func(cfg registry.Config) (*TestProbe, error) {
		return &TestProbe{name: "probe-2"}, nil
	})

	assert.Equal(t, 2, r.Count())
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := registry.New[*TestProbe]("test")

	// Register a probe
	r.Register("test", func(cfg registry.Config) (*TestProbe, error) {
		return &TestProbe{name: "test"}, nil
	})

	// Simulate concurrent access
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			probe, err := r.Create("test", registry.Config{})
			assert.NoError(t, err)
			assert.NotNil(t, probe)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
