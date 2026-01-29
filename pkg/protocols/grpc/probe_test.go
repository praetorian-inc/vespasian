package grpc

import (
	"context"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/probes"
)

func TestGRPCProbe_Name(t *testing.T) {
	probe := NewGRPCProbe()

	if probe.Name() != "grpc" {
		t.Errorf("Name() = %s, want grpc", probe.Name())
	}
}

func TestGRPCProbe_Category(t *testing.T) {
	probe := NewGRPCProbe()

	if probe.Category() != probes.CategoryProtocol {
		t.Errorf("Category() = %s, want %s", probe.Category(), probes.CategoryProtocol)
	}
}

func TestGRPCProbe_Priority(t *testing.T) {
	probe := NewGRPCProbe()

	if probe.Priority() != 60 {
		t.Errorf("Priority() = %d, want 60", probe.Priority())
	}
}

func TestGRPCProbe_Accepts(t *testing.T) {
	probe := NewGRPCProbe()

	tests := []struct {
		name string
		port int
		want bool
	}{
		{
			name: "accepts port 9090 (common gRPC)",
			port: 9090,
			want: true,
		},
		{
			name: "accepts port 50051 (gRPC default)",
			port: 50051,
			want: true,
		},
		{
			name: "accepts port 8080",
			port: 8080,
			want: true,
		},
		{
			name: "rejects port 22",
			port: 22,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := probes.Target{Port: tt.port}
			if got := probe.Accepts(target); got != tt.want {
				t.Errorf("Accepts(%d) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

func TestGRPCProbe_Run(t *testing.T) {
	probe := NewGRPCProbe()

	target := probes.Target{
		Host: "localhost",
		Port: 50051,
	}

	result, err := probe.Run(context.Background(), target, probes.ProbeOptions{Timeout: 5})
	if err != nil {
		// Expected to fail against non-existent server
		t.Logf("Run() error (expected): %v", err)
	}

	if result == nil {
		t.Fatal("Run() returned nil result")
	}

	if result.ProbeCategory != probes.CategoryProtocol {
		t.Errorf("Run() category = %s, want %s", result.ProbeCategory, probes.CategoryProtocol)
	}
}
