package discovery

import (
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/probes"
)

func TestDedupeEndpoints_Empty(t *testing.T) {
	results := []probes.ProbeResult{}
	deduped := DedupeEndpoints(results)

	if len(deduped) != 0 {
		t.Errorf("expected 0 results, got %d", len(deduped))
	}
}

func TestDedupeEndpoints_NoDuplicates(t *testing.T) {
	results := []probes.ProbeResult{
		{
			Success: true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/api/users", Method: "GET"},
				{Path: "/api/posts", Method: "GET"},
			},
		},
	}

	deduped := DedupeEndpoints(results)

	if len(deduped) != 1 {
		t.Fatalf("expected 1 result, got %d", len(deduped))
	}

	if len(deduped[0].Endpoints) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(deduped[0].Endpoints))
	}
}

func TestDedupeEndpoints_WithinSameResult(t *testing.T) {
	results := []probes.ProbeResult{
		{
			Success: true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/api/users", Method: "GET"},
				{Path: "/api/users", Method: "GET"}, // Duplicate
				{Path: "/api/posts", Method: "GET"},
			},
		},
	}

	deduped := DedupeEndpoints(results)

	if len(deduped) != 1 {
		t.Fatalf("expected 1 result, got %d", len(deduped))
	}

	// Should have 2 unique endpoints (users GET, posts GET)
	if len(deduped[0].Endpoints) != 2 {
		t.Errorf("expected 2 unique endpoints, got %d", len(deduped[0].Endpoints))
	}
}

func TestDedupeEndpoints_AcrossResults(t *testing.T) {
	results := []probes.ProbeResult{
		{
			ProbeCategory: probes.CategoryHTTP,
			Success:       true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/api/users", Method: "GET"},
				{Path: "/api/posts", Method: "GET"},
			},
		},
		{
			ProbeCategory: probes.CategoryProtocol,
			Success:       true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/api/users", Method: "GET"}, // Duplicate from first result
				{Path: "/api/comments", Method: "GET"},
			},
		},
	}

	deduped := DedupeEndpoints(results)

	if len(deduped) != 2 {
		t.Fatalf("expected 2 results, got %d", len(deduped))
	}

	// Count total unique endpoints: /api/users GET, /api/posts GET, /api/comments GET
	totalEndpoints := 0
	for _, r := range deduped {
		totalEndpoints += len(r.Endpoints)
	}

	if totalEndpoints != 3 {
		t.Errorf("expected 3 unique endpoints total, got %d", totalEndpoints)
	}

	// First result should have 2 endpoints (users, posts)
	if len(deduped[0].Endpoints) != 2 {
		t.Errorf("expected first result to have 2 endpoints, got %d", len(deduped[0].Endpoints))
	}

	// Second result should have 1 endpoint (comments), users was deduplicated
	if len(deduped[1].Endpoints) != 1 {
		t.Errorf("expected second result to have 1 endpoint, got %d", len(deduped[1].Endpoints))
	}

	// Verify the remaining endpoint in second result is comments
	if deduped[1].Endpoints[0].Path != "/api/comments" {
		t.Errorf("expected /api/comments, got %s", deduped[1].Endpoints[0].Path)
	}
}

func TestDedupeEndpoints_DifferentMethods(t *testing.T) {
	results := []probes.ProbeResult{
		{
			Success: true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/api/users", Method: "GET"},
				{Path: "/api/users", Method: "POST"}, // Same path, different method
				{Path: "/api/users", Method: "GET"},  // Duplicate
			},
		},
	}

	deduped := DedupeEndpoints(results)

	if len(deduped) != 1 {
		t.Fatalf("expected 1 result, got %d", len(deduped))
	}

	// Should keep both GET and POST (different methods)
	if len(deduped[0].Endpoints) != 2 {
		t.Errorf("expected 2 unique endpoints (GET and POST), got %d", len(deduped[0].Endpoints))
	}

	// Verify both methods are present
	methods := make(map[string]bool)
	for _, ep := range deduped[0].Endpoints {
		methods[ep.Method] = true
	}

	if !methods["GET"] || !methods["POST"] {
		t.Error("expected both GET and POST methods to be present")
	}
}

func TestDedupeEndpoints_PreservesFailedResults(t *testing.T) {
	results := []probes.ProbeResult{
		{
			Success: true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/api/users", Method: "GET"},
			},
		},
		{
			Success: false,
			Error:   probes.ErrProbeTimeout,
		},
	}

	deduped := DedupeEndpoints(results)

	if len(deduped) != 2 {
		t.Fatalf("expected 2 results, got %d", len(deduped))
	}

	// Failed result should remain unchanged
	if deduped[1].Success {
		t.Error("expected second result to remain unsuccessful")
	}
}

func TestDedupeEndpoints_EmptyEndpointsResult(t *testing.T) {
	results := []probes.ProbeResult{
		{
			Success:   true,
			Endpoints: []probes.APIEndpoint{}, // Empty but successful
		},
		{
			Success: true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/api/users", Method: "GET"},
			},
		},
	}

	deduped := DedupeEndpoints(results)

	if len(deduped) != 2 {
		t.Fatalf("expected 2 results, got %d", len(deduped))
	}

	// First result should remain with 0 endpoints
	if len(deduped[0].Endpoints) != 0 {
		t.Errorf("expected first result to have 0 endpoints, got %d", len(deduped[0].Endpoints))
	}
}

func TestDedupeEndpoints_CaseInsensitivePaths(t *testing.T) {
	results := []probes.ProbeResult{
		{
			Success: true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/API/Users", Method: "GET"},
				{Path: "/api/users", Method: "GET"}, // Should be considered same (case-insensitive)
			},
		},
	}

	deduped := DedupeEndpoints(results)

	if len(deduped) != 1 {
		t.Fatalf("expected 1 result, got %d", len(deduped))
	}

	// Should deduplicate case-insensitive paths
	if len(deduped[0].Endpoints) != 1 {
		t.Errorf("expected 1 endpoint (case-insensitive deduplication), got %d", len(deduped[0].Endpoints))
	}
}
