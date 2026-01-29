package probes

import "context"

// HTTPProbe extends Probe for HTTP-specific API discovery.
type HTTPProbe interface {
	Probe

	// ScanEndpoints discovers API endpoints on HTTP services
	ScanEndpoints(ctx context.Context, target Target) ([]APIEndpoint, error)
}
