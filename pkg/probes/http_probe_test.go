package probes_test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/probes"
	"github.com/stretchr/testify/assert"
)

// TestHTTPProbe implements HTTPProbe for testing
type TestHTTPProbe struct {
	TestProbe
}

func (p *TestHTTPProbe) ScanEndpoints(ctx context.Context, target probes.Target) ([]probes.APIEndpoint, error) {
	return []probes.APIEndpoint{
		{Path: "/api/v1/users", Method: "GET"},
		{Path: "/api/v1/posts", Method: "POST"},
	}, nil
}

func TestHTTPProbeInterface(t *testing.T) {
	var _ probes.HTTPProbe = (*TestHTTPProbe)(nil)

	probe := &TestHTTPProbe{}
	ctx := context.Background()
	target := probes.Target{Host: "example.com", Port: 443}

	endpoints, err := probe.ScanEndpoints(ctx, target)
	assert.NoError(t, err)
	assert.Len(t, endpoints, 2)
	assert.Equal(t, "/api/v1/users", endpoints[0].Path)
	assert.Equal(t, "GET", endpoints[0].Method)
}
