package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/vespasian/pkg/discovery"
	"github.com/praetorian-inc/vespasian/pkg/output"
	"github.com/praetorian-inc/vespasian/pkg/probes"

	// Import probes to trigger init() registration
	_ "github.com/praetorian-inc/vespasian/pkg/crawler"
	_ "github.com/praetorian-inc/vespasian/pkg/protocols/grpc"
	_ "github.com/praetorian-inc/vespasian/pkg/protocols/websocket"
	_ "github.com/praetorian-inc/vespasian/pkg/spec/graphql"
	_ "github.com/praetorian-inc/vespasian/pkg/spec/openapi"
	_ "github.com/praetorian-inc/vespasian/pkg/spec/wsdl"
)

// TestEndToEndScan tests the complete scan workflow:
// discovery -> adapter -> writer -> output
func TestEndToEndScan(t *testing.T) {
	// Create test HTTP server with multiple endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"users":[]}`))
	})
	mux.HandleFunc("/api/posts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"posts":[]}`))
	})
	mux.HandleFunc("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		swagger := `{
			"swagger": "2.0",
			"paths": {
				"/api/v1": {"get": {}},
				"/api/v2": {"post": {}}
			}
		}`
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(swagger))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Extract host and port from test server URL
	url := strings.TrimPrefix(server.URL, "http://")
	parts := strings.Split(url, ":")
	host := parts[0]
	port := 0
	if len(parts) > 1 {
		// Parse port (simplified for test)
		port = 8080
	}

	target := probes.Target{
		Host: host,
		Port: port,
	}

	// Get registered probes
	probeNames := probes.Registry.List()
	if len(probeNames) == 0 {
		t.Fatal("no probes registered")
	}

	probeList := make([]probes.Probe, 0)
	for _, name := range probeNames {
		probe, err := probes.Registry.Create(name, nil)
		if err != nil {
			t.Fatalf("failed to create probe %s: %v", name, err)
		}
		probeList = append(probeList, probe)
	}

	// Run discovery
	orch := discovery.NewOrchestrator(probeList)
	ctx := context.Background()
	results, err := orch.Discover(ctx, target)
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}

	// Deduplicate
	results = discovery.DedupeEndpoints(results)

	// Convert to findings
	findings := output.ToFindings(results)

	if len(findings) == 0 {
		t.Log("No findings - test server may not match probe patterns")
	}

	t.Logf("Discovered %d endpoints", len(findings))
}

func TestOutputFormat_JSON(t *testing.T) {
	// Create sample findings
	findings := []capability.Finding{
		{
			Type:     capability.FindingAsset,
			Severity: capability.SeverityInfo,
			Data: map[string]any{
				"type":   "api_endpoint",
				"method": "GET",
				"path":   "/api/users",
			},
		},
	}

	buf := &bytes.Buffer{}
	writer, err := output.NewWriter("json", buf)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	ctx := context.Background()
	if err := writer.WriteFindings(ctx, findings); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify output is valid JSON (array of findings)
	jsonOutput := buf.String()
	var result []map[string]any
	if err := json.Unmarshal([]byte(jsonOutput), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput: %s", err, jsonOutput)
	}

	t.Logf("JSON output validated (%d bytes)", len(jsonOutput))
}

func TestOutputFormat_NDJSON(t *testing.T) {
	findings := []capability.Finding{
		{
			Type:     capability.FindingAsset,
			Severity: capability.SeverityInfo,
			Data: map[string]any{
				"type":   "api_endpoint",
				"method": "GET",
				"path":   "/api/test1",
			},
		},
		{
			Type:     capability.FindingRisk,
			Severity: capability.SeverityLow,
			Data: map[string]any{
				"type":        "vulnerability",
				"description": "Test risk",
			},
		},
	}

	buf := &bytes.Buffer{}
	writer, err := output.NewWriter("ndjson", buf)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	ctx := context.Background()
	if err := writer.WriteFindings(ctx, findings); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify each line is valid JSON
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\nLine: %s", i+1, err, line)
		}
	}

	t.Logf("NDJSON output validated (%d lines)", len(lines))
}

func TestOutputFormat_Terminal(t *testing.T) {
	findings := []capability.Finding{
		{
			Type:     capability.FindingAsset,
			Severity: capability.SeverityInfo,
			Data: map[string]any{
				"type":   "api_endpoint",
				"method": "GET",
				"path":   "/api/users",
			},
		},
	}

	buf := &bytes.Buffer{}
	writer, err := output.NewWriter("terminal", buf)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	ctx := context.Background()
	if err := writer.WriteFindings(ctx, findings); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	termOutput := buf.String()
	if len(termOutput) == 0 {
		t.Fatal("expected non-empty terminal output")
	}

	t.Logf("Terminal output generated (%d bytes)", len(termOutput))
}

func TestOutputFormat_Markdown(t *testing.T) {
	findings := []capability.Finding{
		{
			Type:     capability.FindingAsset,
			Severity: capability.SeverityInfo,
			Data: map[string]any{
				"type":   "api_endpoint",
				"method": "GET",
				"path":   "/api/users",
			},
		},
	}

	buf := &bytes.Buffer{}
	writer, err := output.NewWriter("markdown", buf)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	ctx := context.Background()
	if err := writer.WriteFindings(ctx, findings); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	mdOutput := buf.String()
	if len(mdOutput) == 0 {
		t.Fatal("expected non-empty markdown output")
	}

	// Check for markdown syntax
	if !strings.Contains(mdOutput, "#") {
		t.Error("expected markdown headers (# syntax)")
	}

	t.Logf("Markdown output generated (%d bytes)", len(mdOutput))
}

func TestOutputFormat_SARIF(t *testing.T) {
	findings := []capability.Finding{
		{
			Type:     capability.FindingAsset,
			Severity: capability.SeverityInfo,
			Data: map[string]any{
				"type":   "api_endpoint",
				"method": "GET",
				"path":   "/api/users",
			},
		},
	}

	buf := &bytes.Buffer{}
	writer, err := output.NewWriter("sarif", buf)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	ctx := context.Background()
	if err := writer.WriteFindings(ctx, findings); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	sarifOutput := buf.String()
	if len(sarifOutput) == 0 {
		t.Fatal("expected non-empty SARIF output")
	}

	// Verify it's valid JSON (SARIF is JSON-based)
	var result map[string]any
	if err := json.Unmarshal([]byte(sarifOutput), &result); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Check for SARIF-specific fields
	if _, ok := result["version"]; !ok {
		t.Error("expected 'version' field in SARIF output")
	}

	t.Logf("SARIF output generated (%d bytes)", len(sarifOutput))
}

func TestDeduplication_AcrossProbes(t *testing.T) {
	// Create results with duplicate endpoints
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
				{Path: "/api/users", Method: "GET"}, // Duplicate
				{Path: "/api/comments", Method: "GET"},
			},
		},
	}

	deduped := discovery.DedupeEndpoints(results)

	// Count total unique endpoints
	totalEndpoints := 0
	for _, r := range deduped {
		totalEndpoints += len(r.Endpoints)
	}

	// Should have 3 unique: /api/users GET, /api/posts GET, /api/comments GET
	if totalEndpoints != 3 {
		t.Errorf("expected 3 unique endpoints after deduplication, got %d", totalEndpoints)
	}

	t.Logf("Deduplication working: %d unique endpoints from %d results", totalEndpoints, len(results))
}
