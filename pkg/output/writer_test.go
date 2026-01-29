package output

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
)

func TestNewWriter_Terminal(t *testing.T) {
	buf := &bytes.Buffer{}
	writer, err := NewWriter("terminal", buf)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if writer == nil {
		t.Fatal("expected writer to be created")
	}
}

func TestNewWriter_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	writer, err := NewWriter("json", buf)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if writer == nil {
		t.Fatal("expected writer to be created")
	}
}

func TestNewWriter_NDJSON(t *testing.T) {
	buf := &bytes.Buffer{}
	writer, err := NewWriter("ndjson", buf)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if writer == nil {
		t.Fatal("expected writer to be created")
	}
}

func TestNewWriter_Markdown(t *testing.T) {
	buf := &bytes.Buffer{}
	writer, err := NewWriter("markdown", buf)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if writer == nil {
		t.Fatal("expected writer to be created")
	}
}

func TestNewWriter_SARIF(t *testing.T) {
	buf := &bytes.Buffer{}
	writer, err := NewWriter("sarif", buf)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if writer == nil {
		t.Fatal("expected writer to be created")
	}
}

func TestNewWriter_InvalidFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	_, err := NewWriter("invalid", buf)
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestWriter_WriteFindings_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	writer, err := NewWriter("json", buf)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	findings := []capability.Finding{
		{
			Type:     capability.FindingAsset,
			Severity: capability.SeverityInfo,
			Data: map[string]any{
				"type":   "api_endpoint",
				"method": "GET",
				"path":   "/api/test",
			},
		},
	}

	ctx := context.Background()
	if err := writer.WriteFindings(ctx, findings); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "GET") {
		t.Errorf("expected output to contain 'GET', got: %s", output)
	}
}

func TestWriter_WriteFindings_Terminal(t *testing.T) {
	buf := &bytes.Buffer{}
	writer, err := NewWriter("terminal", buf)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

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

	ctx := context.Background()
	if err := writer.WriteFindings(ctx, findings); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "GET /api/users") {
		t.Errorf("expected output to contain 'GET /api/users', got: %s", output)
	}
}

func TestWriter_WriteFindings_Empty(t *testing.T) {
	buf := &bytes.Buffer{}
	writer, err := NewWriter("json", buf)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	findings := []capability.Finding{}

	ctx := context.Background()
	if err := writer.WriteFindings(ctx, findings); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Should produce valid but empty output
	output := buf.String()
	if len(output) == 0 {
		t.Error("expected some output even for empty findings")
	}
}

func TestWriter_CloseWithoutWrite(t *testing.T) {
	buf := &bytes.Buffer{}
	writer, err := NewWriter("json", buf)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Close without writing anything
	if err := writer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}
