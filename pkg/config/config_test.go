package config_test

import (
	"os"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_LoadFromYAML(t *testing.T) {
	yamlData := `
probes:
  - name: http-discovery
    enabled: true
  - name: protocol-detection
    enabled: false

targets:
  - host: example.com
    port: 443
  - host: api.example.com
    port: 80

timeout: 30
concurrency: 10
`

	// Write to temp file
	tmpfile, err := os.CreateTemp("", "vespasian-test-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString(yamlData)
	require.NoError(t, err)
	tmpfile.Close()

	// Load config
	cfg, err := config.Load(tmpfile.Name())
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	// Verify values
	assert.Len(t, cfg.Probes, 2)
	assert.Equal(t, "http-discovery", cfg.Probes[0].Name)
	assert.True(t, cfg.Probes[0].Enabled)
	assert.Equal(t, "protocol-detection", cfg.Probes[1].Name)
	assert.False(t, cfg.Probes[1].Enabled)

	assert.Len(t, cfg.Targets, 2)
	assert.Equal(t, "example.com", cfg.Targets[0].Host)
	assert.Equal(t, 443, cfg.Targets[0].Port)

	assert.Equal(t, 30, cfg.Timeout)
	assert.Equal(t, 10, cfg.Concurrency)
}

func TestConfig_LoadNonExistent(t *testing.T) {
	_, err := config.Load("/nonexistent/config.yaml")
	assert.Error(t, err)
}

func TestConfig_DefaultValues(t *testing.T) {
	cfg := config.Config{}

	// Should have sensible defaults
	assert.Equal(t, 0, cfg.Timeout)
	assert.Equal(t, 0, cfg.Concurrency)
	assert.Empty(t, cfg.Probes)
	assert.Empty(t, cfg.Targets)
}

func TestConfig_InvalidYAML(t *testing.T) {
	invalidYAML := `
probes:
  - invalid yaml structure
    bad: [nested
`

	tmpfile, err := os.CreateTemp("", "vespasian-invalid-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString(invalidYAML)
	require.NoError(t, err)
	tmpfile.Close()

	_, err = config.Load(tmpfile.Name())
	assert.Error(t, err)
}

func TestProbeConfig(t *testing.T) {
	pc := config.ProbeConfig{
		Name:    "test-probe",
		Enabled: true,
	}

	assert.Equal(t, "test-probe", pc.Name)
	assert.True(t, pc.Enabled)
}

func TestTargetConfig(t *testing.T) {
	tc := config.TargetConfig{
		Host: "example.com",
		Port: 443,
	}

	assert.Equal(t, "example.com", tc.Host)
	assert.Equal(t, 443, tc.Port)
}
