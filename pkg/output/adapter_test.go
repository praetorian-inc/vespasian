package output

import (
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/vespasian/pkg/probes"
)

func TestToFindings_EmptyResult(t *testing.T) {
	results := []probes.ProbeResult{}
	findings := ToFindings(results)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestToFindings_SingleEndpoint(t *testing.T) {
	results := []probes.ProbeResult{
		{
			ProbeCategory: probes.CategoryHTTP,
			Success:       true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/api/users", Method: "GET"},
			},
			Error: nil,
		},
	}

	findings := ToFindings(results)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Type != capability.FindingAsset {
		t.Errorf("expected asset type, got %s", f.Type)
	}
	if f.Severity != capability.SeverityInfo {
		t.Errorf("expected info severity, got %s", f.Severity)
	}

	// Check data fields
	if f.Data["type"] != "api_endpoint" {
		t.Errorf("expected type=api_endpoint, got %v", f.Data["type"])
	}
	if f.Data["method"] != "GET" {
		t.Errorf("expected method=GET, got %v", f.Data["method"])
	}
	if f.Data["path"] != "/api/users" {
		t.Errorf("expected path=/api/users, got %v", f.Data["path"])
	}
}

func TestToFindings_MultipleEndpoints(t *testing.T) {
	results := []probes.ProbeResult{
		{
			ProbeCategory: probes.CategoryHTTP,
			Success:       true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/api/users", Method: "GET"},
				{Path: "/api/users", Method: "POST"},
				{Path: "/api/posts", Method: "GET"},
			},
			Error: nil,
		},
	}

	findings := ToFindings(results)

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
}

func TestToFindings_ProbeError(t *testing.T) {
	results := []probes.ProbeResult{
		{
			ProbeCategory: probes.CategoryHTTP,
			Success:       false,
			Endpoints:     nil,
			Error:         probes.ErrProbeTimeout,
		},
	}

	findings := ToFindings(results)

	// Should create error finding
	if len(findings) != 1 {
		t.Fatalf("expected 1 error finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Type != capability.FindingAttribute {
		t.Errorf("expected attribute type for error, got %s", f.Type)
	}
	if f.Data["type"] != "probe_error" {
		t.Errorf("expected type=probe_error, got %v", f.Data["type"])
	}
	if f.Data["error"] == nil {
		t.Error("expected error field in data")
	}
}

func TestToFindings_MixedResults(t *testing.T) {
	results := []probes.ProbeResult{
		{
			ProbeCategory: probes.CategoryHTTP,
			Success:       true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/api/v1", Method: "GET"},
			},
		},
		{
			ProbeCategory: probes.CategoryProtocol,
			Success:       false,
			Error:         probes.ErrConnectionRefused,
		},
		{
			ProbeCategory: probes.CategoryProtocol,
			Success:       true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/grpc.Service/Method", Method: "POST"},
			},
		},
	}

	findings := ToFindings(results)

	// Should create findings for successful results + 1 error finding
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings (2 endpoints + 1 error), got %d", len(findings))
	}

	// Count findings by type
	assetCount := 0
	errorCount := 0
	for _, f := range findings {
		if f.Type == capability.FindingAsset {
			assetCount++
		} else if f.Type == capability.FindingAttribute && f.Data["type"] == "probe_error" {
			errorCount++
		}
	}

	if assetCount != 2 {
		t.Errorf("expected 2 asset findings, got %d", assetCount)
	}
	if errorCount != 1 {
		t.Errorf("expected 1 error finding, got %d", errorCount)
	}
}

func TestToFindings_MetadataFields(t *testing.T) {
	results := []probes.ProbeResult{
		{
			ProbeCategory: probes.CategoryHTTP,
			Success:       true,
			Endpoints: []probes.APIEndpoint{
				{Path: "/api/users", Method: "GET"},
			},
		},
	}

	findings := ToFindings(results)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]

	// Check data contains probe category
	if f.Data == nil {
		t.Fatal("expected data to be populated")
	}

	category, ok := f.Data["probe_category"]
	if !ok {
		t.Error("expected probe_category in data")
	}
	if category != "http" {
		t.Errorf("expected probe_category 'http', got %v", category)
	}

	// Check data contains method
	method, ok := f.Data["method"]
	if !ok {
		t.Error("expected method in data")
	}
	if method != "GET" {
		t.Errorf("expected method 'GET', got %v", method)
	}

	// Check data contains path
	path, ok := f.Data["path"]
	if !ok {
		t.Error("expected path in data")
	}
	if path != "/api/users" {
		t.Errorf("expected path '/api/users', got %v", path)
	}
}
