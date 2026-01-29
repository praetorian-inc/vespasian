package grpc

import (
	"context"

	"github.com/praetorian-inc/vespasian/pkg/probes"
	"github.com/praetorian-inc/vespasian/pkg/registry"
)

func init() {
	probes.Registry.Register("grpc", func(cfg registry.Config) (probes.Probe, error) {
		return NewGRPCProbe(), nil
	})
}

// GRPCProbe implements probes.Probe for gRPC reflection-based service discovery
type GRPCProbe struct{}

// NewGRPCProbe creates a new gRPC probe
func NewGRPCProbe() *GRPCProbe {
	return &GRPCProbe{}
}

// Name returns the probe name
func (p *GRPCProbe) Name() string {
	return "grpc"
}

// Category returns the probe category
func (p *GRPCProbe) Category() probes.ProbeCategory {
	return probes.CategoryProtocol
}

// Priority returns execution priority (higher = earlier)
func (p *GRPCProbe) Priority() int {
	return 60 // High priority for protocol detection
}

// Accepts returns true if probe can scan the target
func (p *GRPCProbe) Accepts(target probes.Target) bool {
	// Accept common gRPC ports
	switch target.Port {
	case 9090, 50051, 8080, 8443, 443:
		return true
	default:
		return false
	}
}

// Run executes the gRPC probe
func (p *GRPCProbe) Run(ctx context.Context, target probes.Target, opts probes.ProbeOptions) (*probes.ProbeResult, error) {
	// TODO: Implement gRPC reflection
	// For now, return a basic result structure
	return &probes.ProbeResult{
		ProbeCategory: p.Category(),
		Success:       false,
		Endpoints:     []probes.APIEndpoint{},
	}, nil
}
