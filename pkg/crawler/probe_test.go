package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrawlerProbe_Name(t *testing.T) {
	probe := NewCrawlerProbe(&CrawlerConfig{
		MaxDepth: 2,
		MaxPages: 100,
	})

	assert.Equal(t, "crawler", probe.Name())
}

func TestCrawlerProbe_Category(t *testing.T) {
	probe := NewCrawlerProbe(&CrawlerConfig{
		MaxDepth: 2,
		MaxPages: 100,
	})

	assert.Equal(t, probes.CategoryHTTP, probe.Category())
}

func TestCrawlerProbe_Priority(t *testing.T) {
	probe := NewCrawlerProbe(&CrawlerConfig{
		MaxDepth: 2,
		MaxPages: 100,
	})

	assert.Equal(t, 100, probe.Priority())
}

func TestCrawlerProbe_Accepts(t *testing.T) {
	probe := NewCrawlerProbe(&CrawlerConfig{
		MaxDepth: 2,
		MaxPages: 100,
	})

	tests := []struct {
		name   string
		target probes.Target
		want   bool
	}{
		{"HTTP port 80", probes.Target{Host: "example.com", Port: 80}, true},
		{"HTTPS port 443", probes.Target{Host: "example.com", Port: 443}, true},
		{"HTTP alt port 8080", probes.Target{Host: "example.com", Port: 8080}, true},
		{"SSH port", probes.Target{Host: "example.com", Port: 22}, false},
		{"MySQL port", probes.Target{Host: "example.com", Port: 3306}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := probe.Accepts(tt.target)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCrawlerProbe_Run_Success(t *testing.T) {
	// Create test server with links
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			w.Write([]byte(`
				<html>
				<body>
					<a href="/page1">Page 1</a>
					<a href="/page2">Page 2</a>
				</body>
				</html>
			`))
		} else if r.URL.Path == "/page1" {
			w.Write([]byte(`<html><body><a href="/page3">Page 3</a></body></html>`))
		} else {
			w.Write([]byte(`<html><body><p>Test page</p></body></html>`))
		}
	}))
	defer server.Close()

	probe := NewCrawlerProbe(&CrawlerConfig{
		MaxDepth: 2,
		MaxPages: 10,
	})

	// Extract host and port from test server
	target := probes.Target{Host: server.URL, Port: 80}
	opts := probes.ProbeOptions{Timeout: 5}

	ctx := context.Background()
	result, err := probe.Run(ctx, target, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, probes.CategoryHTTP, result.ProbeCategory)
	assert.Greater(t, len(result.Endpoints), 0)
}

func TestCrawlerProbe_Run_MaxDepth(t *testing.T) {
	depth := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		depth++
		w.Write([]byte(`<html><body><a href="/level` + string(rune(depth)) + `">Next</a></body></html>`))
	}))
	defer server.Close()

	probe := NewCrawlerProbe(&CrawlerConfig{
		MaxDepth: 2,
		MaxPages: 100,
	})

	target := probes.Target{Host: server.URL, Port: 80}
	opts := probes.ProbeOptions{Timeout: 5}

	ctx := context.Background()
	result, err := probe.Run(ctx, target, opts)

	require.NoError(t, err)
	assert.True(t, result.Success)
	// Should stop at max depth
	assert.LessOrEqual(t, depth, 3) // Root + 2 levels
}

func TestCrawlerProbe_Run_MaxPages(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		requestCount++
		// Generate many links
		html := `<html><body>`
		for i := 0; i < 10; i++ {
			html += `<a href="/page` + string(rune(i)) + `">Page</a>`
		}
		html += `</body></html>`
		w.Write([]byte(html))
	}))
	defer server.Close()

	probe := NewCrawlerProbe(&CrawlerConfig{
		MaxDepth: 5,
		MaxPages: 3, // Limit to 3 pages
	})

	target := probes.Target{Host: server.URL, Port: 80}
	opts := probes.ProbeOptions{Timeout: 5}

	ctx := context.Background()
	result, err := probe.Run(ctx, target, opts)

	require.NoError(t, err)
	assert.True(t, result.Success)
	// Should stop at max pages
	assert.LessOrEqual(t, requestCount, 3)
}
