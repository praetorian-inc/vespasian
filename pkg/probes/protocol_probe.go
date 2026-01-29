package probes

import "context"

// ProtocolInfo contains information about a detected protocol.
type ProtocolInfo struct {
	Name    string
	Version string
}

// ProtocolProbe extends Probe for protocol detection.
type ProtocolProbe interface {
	Probe

	// DetectProtocol identifies the protocol running on a target
	DetectProtocol(ctx context.Context, target Target) (*ProtocolInfo, error)
}
