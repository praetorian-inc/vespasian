package discovery

import (
	"context"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/probes"
)

// mockProbe implements probes.Probe for testing.
type mockProbe struct {
	name      string
	category  probes.ProbeCategory
	priority  int
	accepts   bool
	endpoints []probes.APIEndpoint
	err       error
}

func (m *mockProbe) Run(ctx context.Context, target probes.Target, opts probes.ProbeOptions) (*probes.ProbeResult, error) {
	if m.err != nil {
		return &probes.ProbeResult{
			ProbeCategory: m.category,
			Success:       false,
			Error:         m.err,
		}, m.err
	}
	return &probes.ProbeResult{
		ProbeCategory: m.category,
		Success:       true,
		Endpoints:     m.endpoints,
	}, nil
}

func (m *mockProbe) Name() string { return m.name }

func (m *mockProbe) Category() probes.ProbeCategory { return m.category }

func (m *mockProbe) Priority() int { return m.priority }

func (m *mockProbe) Accepts(target probes.Target) bool { return m.accepts }

func TestNewOrchestrator(t *testing.T) {
	probeList := []probes.Probe{
		&mockProbe{name: "test1", priority: 10, accepts: true},
	}

	orch := NewOrchestrator(probeList)
	if orch == nil {
		t.Fatal("expected orchestrator to be created")
	}
}

func TestOrchestrator_SortsByPriority(t *testing.T) {
	probeList := []probes.Probe{
		&mockProbe{name: "low", priority: 10, accepts: true},
		&mockProbe{name: "high", priority: 100, accepts: true},
		&mockProbe{name: "medium", priority: 50, accepts: true},
	}

	orch := NewOrchestrator(probeList)

	// Run discovery (this will internally sort)
	target := probes.Target{Host: "example.com", Port: 443}
	ctx := context.Background()
	results, err := orch.Discover(ctx, target)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// We can't directly test internal sorting, but we can verify all probes ran
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
}

func TestOrchestrator_Discover_Success(t *testing.T) {
	probeList := []probes.Probe{
		&mockProbe{
			name:     "probe1",
			priority: 10,
			accepts:  true,
			endpoints: []probes.APIEndpoint{
				{Path: "/api/v1", Method: "GET"},
			},
		},
	}

	orch := NewOrchestrator(probeList)
	target := probes.Target{Host: "example.com", Port: 443}
	ctx := context.Background()

	results, err := orch.Discover(ctx, target)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if !results[0].Success {
		t.Error("expected successful result")
	}

	if len(results[0].Endpoints) != 1 {
		t.Errorf("expected 1 endpoint, got %d", len(results[0].Endpoints))
	}
}

func TestOrchestrator_Discover_MultipleProbes(t *testing.T) {
	probeList := []probes.Probe{
		&mockProbe{
			name:     "probe1",
			priority: 100,
			accepts:  true,
			endpoints: []probes.APIEndpoint{
				{Path: "/api/v1", Method: "GET"},
			},
		},
		&mockProbe{
			name:     "probe2",
			priority: 50,
			accepts:  true,
			endpoints: []probes.APIEndpoint{
				{Path: "/api/v2", Method: "POST"},
			},
		},
	}

	orch := NewOrchestrator(probeList)
	target := probes.Target{Host: "example.com", Port: 443}
	ctx := context.Background()

	results, err := orch.Discover(ctx, target)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Count total endpoints
	totalEndpoints := 0
	for _, r := range results {
		totalEndpoints += len(r.Endpoints)
	}
	if totalEndpoints != 2 {
		t.Errorf("expected 2 total endpoints, got %d", totalEndpoints)
	}
}

func TestOrchestrator_Discover_SkipsNonAcceptingProbes(t *testing.T) {
	probeList := []probes.Probe{
		&mockProbe{
			name:     "accepts",
			priority: 100,
			accepts:  true,
			endpoints: []probes.APIEndpoint{
				{Path: "/api", Method: "GET"},
			},
		},
		&mockProbe{
			name:     "rejects",
			priority: 50,
			accepts:  false, // Should be skipped
			endpoints: []probes.APIEndpoint{
				{Path: "/should-not-appear", Method: "GET"},
			},
		},
	}

	orch := NewOrchestrator(probeList)
	target := probes.Target{Host: "example.com", Port: 443}
	ctx := context.Background()

	results, err := orch.Discover(ctx, target)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// Only the accepting probe should run
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Endpoints[0].Path == "/should-not-appear" {
		t.Error("non-accepting probe ran when it shouldn't")
	}
}

func TestOrchestrator_Discover_HandlesErrors(t *testing.T) {
	probeList := []probes.Probe{
		&mockProbe{
			name:     "failing",
			priority: 100,
			accepts:  true,
			err:      probes.ErrProbeTimeout,
		},
		&mockProbe{
			name:     "succeeding",
			priority: 50,
			accepts:  true,
			endpoints: []probes.APIEndpoint{
				{Path: "/api", Method: "GET"},
			},
		},
	}

	orch := NewOrchestrator(probeList)
	target := probes.Target{Host: "example.com", Port: 443}
	ctx := context.Background()

	results, err := orch.Discover(ctx, target)
	if err != nil {
		t.Fatalf("Discover should not fail on probe errors: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results (including error), got %d", len(results))
	}

	// First result should be the error
	if results[0].Success {
		t.Error("expected first result to be unsuccessful")
	}
	if results[0].Error == nil {
		t.Error("expected error in first result")
	}

	// Second result should succeed
	if !results[1].Success {
		t.Error("expected second result to succeed")
	}
}

func TestOrchestrator_Discover_ConcurrentExecution(t *testing.T) {
	// Create multiple probes that would benefit from concurrency
	probeList := make([]probes.Probe, 10)
	for i := 0; i < 10; i++ {
		probeList[i] = &mockProbe{
			name:     "probe",
			priority: 100 - i, // Different priorities
			accepts:  true,
			endpoints: []probes.APIEndpoint{
				{Path: "/api", Method: "GET"},
			},
		}
	}

	orch := NewOrchestrator(probeList)
	target := probes.Target{Host: "example.com", Port: 443}
	ctx := context.Background()

	results, err := orch.Discover(ctx, target)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// All 10 probes should run
	if len(results) != 10 {
		t.Errorf("expected 10 results, got %d", len(results))
	}
}
