package probes_test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/probes"
	"github.com/stretchr/testify/assert"
)

// TestProbe implements the Probe interface for testing
type TestProbe struct{}

func (p *TestProbe) Run(ctx context.Context, target probes.Target, opts probes.ProbeOptions) (*probes.ProbeResult, error) {
	return &probes.ProbeResult{
		ProbeCategory: probes.CategoryHTTP,
		Success:       true,
		Endpoints:     []probes.APIEndpoint{},
	}, nil
}

func (p *TestProbe) Name() string {
	return "test-probe"
}

func (p *TestProbe) Category() probes.ProbeCategory {
	return probes.CategoryHTTP
}

func (p *TestProbe) Priority() int {
	return 100
}

func (p *TestProbe) Accepts(target probes.Target) bool {
	return target.Host != ""
}

func TestProbeInterface(t *testing.T) {
	var _ probes.Probe = (*TestProbe)(nil)

	probe := &TestProbe{}
	assert.Equal(t, "test-probe", probe.Name())
	assert.Equal(t, probes.CategoryHTTP, probe.Category())
	assert.Equal(t, 100, probe.Priority())

	target := probes.Target{Host: "example.com"}
	assert.True(t, probe.Accepts(target))
}

func TestProbeRun(t *testing.T) {
	probe := &TestProbe{}
	ctx := context.Background()
	target := probes.Target{Host: "example.com"}
	opts := probes.ProbeOptions{}

	result, err := probe.Run(ctx, target, opts)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, probes.CategoryHTTP, result.ProbeCategory)
}

func TestProbeCategoryString(t *testing.T) {
	assert.Equal(t, "http", probes.CategoryHTTP.String())
	assert.Equal(t, "protocol", probes.CategoryProtocol.String())
}

func TestTargetValidation(t *testing.T) {
	// Valid target
	target := probes.Target{
		Host: "example.com",
		Port: 443,
	}
	assert.Equal(t, "example.com", target.Host)
	assert.Equal(t, 443, target.Port)

	// Empty target
	emptyTarget := probes.Target{}
	assert.Empty(t, emptyTarget.Host)
}
