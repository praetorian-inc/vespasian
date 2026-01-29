package probes_test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/probes"
	"github.com/stretchr/testify/assert"
)

// TestProtocolProbe implements ProtocolProbe for testing
type TestProtocolProbe struct {
	TestProbe
}

func (p *TestProtocolProbe) DetectProtocol(ctx context.Context, target probes.Target) (*probes.ProtocolInfo, error) {
	return &probes.ProtocolInfo{
		Name:    "HTTP",
		Version: "1.1",
	}, nil
}

func TestProtocolProbeInterface(t *testing.T) {
	var _ probes.ProtocolProbe = (*TestProtocolProbe)(nil)

	probe := &TestProtocolProbe{}
	ctx := context.Background()
	target := probes.Target{Host: "example.com", Port: 80}

	info, err := probe.DetectProtocol(ctx, target)
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "HTTP", info.Name)
	assert.Equal(t, "1.1", info.Version)
}
