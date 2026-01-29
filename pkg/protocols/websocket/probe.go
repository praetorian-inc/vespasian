package websocket

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/praetorian-inc/vespasian/pkg/probes"
	"github.com/praetorian-inc/vespasian/pkg/registry"
)

func init() {
	probes.Registry.Register("websocket", func(cfg registry.Config) (probes.Probe, error) {
		return NewWebSocketProbe(), nil
	})
}

// WebSocketProbe implements probes.Probe for WebSocket endpoint detection
type WebSocketProbe struct {
	commonPaths []string
}

// NewWebSocketProbe creates a new WebSocket probe
func NewWebSocketProbe() *WebSocketProbe {
	return &WebSocketProbe{
		commonPaths: []string{
			"/ws",
			"/websocket",
			"/socket.io",
			"/sockjs",
			"/socket",
			"/api/ws",
			"/api/websocket",
		},
	}
}

// Name returns the probe name
func (p *WebSocketProbe) Name() string {
	return "websocket"
}

// Category returns the probe category
func (p *WebSocketProbe) Category() probes.ProbeCategory {
	return probes.CategoryProtocol
}

// Priority returns execution priority (higher = earlier)
func (p *WebSocketProbe) Priority() int {
	return 55 // Medium-high priority
}

// Accepts returns true if probe can scan the target
func (p *WebSocketProbe) Accepts(target probes.Target) bool {
	// Accept HTTP/HTTPS ports
	switch target.Port {
	case 80, 443, 8080, 8443, 3000, 5000:
		return true
	default:
		return false
	}
}

// Run executes the WebSocket probe
func (p *WebSocketProbe) Run(ctx context.Context, target probes.Target, opts probes.ProbeOptions) (*probes.ProbeResult, error) {
	baseURL, err := buildBaseURL(target)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	var detectedEndpoints []probes.APIEndpoint

	// Try common WebSocket paths
	for _, path := range p.commonPaths {
		// Convert http(s) to ws(s) for WebSocket connection
		wsURL := strings.Replace(baseURL, "http://", "ws://", 1)
		wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
		wsURL += path

		// Try to establish WebSocket connection
		if p.isWebSocketEndpoint(wsURL) {
			detectedEndpoints = append(detectedEndpoints, probes.APIEndpoint{
				Path:   path,
				Method: "UPGRADE",
			})
		}
	}

	success := len(detectedEndpoints) > 0

	return &probes.ProbeResult{
		ProbeCategory: p.Category(),
		Success:       success,
		Endpoints:     detectedEndpoints,
	}, nil
}

// isWebSocketEndpoint checks if the given URL is a WebSocket endpoint
func (p *WebSocketProbe) isWebSocketEndpoint(wsURL string) bool {
	dialer := websocket.Dialer{
		HandshakeTimeout: 5000000000, // 5 seconds
	}

	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		// Check if error indicates WebSocket upgrade was attempted
		// Some errors like connection refused are expected for non-existent endpoints
		return false
	}

	if conn != nil {
		conn.Close()
		return true
	}

	return false
}

// buildBaseURL constructs base URL from target
func buildBaseURL(target probes.Target) (string, error) {
	// Handle case where Host is already a full URL (from httptest)
	if parsed, err := url.Parse(target.Host); err == nil {
		if parsed.Scheme == "http" || parsed.Scheme == "https" {
			return target.Host, nil
		}
	}

	scheme := "http"
	if target.Port == 443 || target.Port == 8443 {
		scheme = "https"
	}

	return fmt.Sprintf("%s://%s:%d", scheme, target.Host, target.Port), nil
}
