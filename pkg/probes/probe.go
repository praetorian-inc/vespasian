// Package probes defines the core probe interfaces and types for API surface enumeration.
package probes

import (
	"context"
	"errors"
)

// Common probe errors
var (
	ErrProbeTimeout       = errors.New("probe timeout")
	ErrConnectionRefused  = errors.New("connection refused")
	ErrInvalidTarget      = errors.New("invalid target")
)

// ProbeCategory represents the category of probe.
type ProbeCategory string

const (
	// CategoryHTTP represents HTTP-based API probes
	CategoryHTTP ProbeCategory = "http"

	// CategoryProtocol represents protocol-specific probes
	CategoryProtocol ProbeCategory = "protocol"
)

// String returns the string representation of ProbeCategory.
func (c ProbeCategory) String() string {
	return string(c)
}

// Target represents a scan target.
type Target struct {
	Host string
	Port int
}

// ProbeOptions contains options for probe execution.
type ProbeOptions struct {
	Timeout int
}

// ProbeResult contains the results of a probe execution.
type ProbeResult struct {
	ProbeCategory ProbeCategory
	Success       bool
	Endpoints     []APIEndpoint
	Error         error
}

// APIEndpoint represents a discovered API endpoint.
type APIEndpoint struct {
	Path   string
	Method string
}

// Probe is the base interface for all probes.
type Probe interface {
	// Run executes the probe against the target
	Run(ctx context.Context, target Target, opts ProbeOptions) (*ProbeResult, error)

	// Name returns the probe name
	Name() string

	// Category returns the probe category
	Category() ProbeCategory

	// Priority returns the execution priority (higher = earlier)
	Priority() int

	// Accepts returns true if this probe can scan the target
	Accepts(target Target) bool
}
