package wsdl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/probes"
)

func TestWSDLProbe_Name(t *testing.T) {
	probe := NewWSDLProbe(&http.Client{})

	if probe.Name() != "wsdl" {
		t.Errorf("Name() = %s, want wsdl", probe.Name())
	}
}

func TestWSDLProbe_Category(t *testing.T) {
	probe := NewWSDLProbe(&http.Client{})

	if probe.Category() != probes.CategoryHTTP {
		t.Errorf("Category() = %s, want %s", probe.Category(), probes.CategoryHTTP)
	}
}

func TestWSDLProbe_Priority(t *testing.T) {
	probe := NewWSDLProbe(&http.Client{})

	if probe.Priority() != 50 {
		t.Errorf("Priority() = %d, want 50", probe.Priority())
	}
}

func TestWSDLProbe_Accepts(t *testing.T) {
	probe := NewWSDLProbe(&http.Client{})

	tests := []struct {
		name string
		port int
		want bool
	}{
		{
			name: "accepts port 80",
			port: 80,
			want: true,
		},
		{
			name: "accepts port 443",
			port: 443,
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

func TestWSDLProbe_Run(t *testing.T) {
	// Load test fixture
	wsdlData, err := os.ReadFile("../../../testdata/wsdl/calculator.wsdl")
	if err != nil {
		t.Skipf("Skipping test - fixture not available: %v", err)
		return
	}

	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("wsdl") != "" || r.URL.Path == "/calculator.wsdl" {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "text/xml")
			w.Write(wsdlData)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	probe := NewWSDLProbe(server.Client())

	target := probes.Target{
		Host: server.URL,
		Port: 80,
	}

	result, err := probe.Run(context.Background(), target, probes.ProbeOptions{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.Success {
		t.Error("Run() success = false, want true")
	}

	if len(result.Endpoints) == 0 {
		t.Error("Run() returned no endpoints")
	}
}
