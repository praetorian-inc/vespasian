package websocket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/praetorian-inc/vespasian/pkg/probes"
)

func TestWebSocketProbe_Name(t *testing.T) {
	probe := NewWebSocketProbe()

	if probe.Name() != "websocket" {
		t.Errorf("Name() = %s, want websocket", probe.Name())
	}
}

func TestWebSocketProbe_Category(t *testing.T) {
	probe := NewWebSocketProbe()

	if probe.Category() != probes.CategoryProtocol {
		t.Errorf("Category() = %s, want %s", probe.Category(), probes.CategoryProtocol)
	}
}

func TestWebSocketProbe_Priority(t *testing.T) {
	probe := NewWebSocketProbe()

	if probe.Priority() != 55 {
		t.Errorf("Priority() = %d, want 55", probe.Priority())
	}
}

func TestWebSocketProbe_Accepts(t *testing.T) {
	probe := NewWebSocketProbe()

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

func TestWebSocketProbe_Run_DetectsWebSocket(t *testing.T) {
	// Create WebSocket server
	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				t.Logf("upgrade error: %v", err)
				return
			}
			defer conn.Close()
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	probe := NewWebSocketProbe()

	// Convert http://host:port to just host:port for target
	urlParts := strings.TrimPrefix(server.URL, "http://")

	target := probes.Target{
		Host: server.URL,
		Port: 80,
	}

	result, err := probe.Run(context.Background(), target, probes.ProbeOptions{Timeout: 5})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.Success {
		t.Error("Run() success = false, want true for WebSocket endpoint")
	}

	// Check that we found the /ws endpoint
	found := false
	for _, ep := range result.Endpoints {
		t.Logf("Found endpoint: %s %s", ep.Method, ep.Path)
		if strings.Contains(ep.Path, "/ws") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Run() did not detect WebSocket endpoint, got %d endpoints", len(result.Endpoints))
	}

	_ = urlParts // silence unused
}

func TestWebSocketProbe_Run_NoWebSocket(t *testing.T) {
	// Create regular HTTP server without WebSocket
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Not a WebSocket"))
	}))
	defer server.Close()

	probe := NewWebSocketProbe()

	target := probes.Target{
		Host: server.URL,
		Port: 80,
	}

	result, err := probe.Run(context.Background(), target, probes.ProbeOptions{Timeout: 5})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Success {
		t.Error("Run() success = true, want false for non-WebSocket endpoint")
	}
}
