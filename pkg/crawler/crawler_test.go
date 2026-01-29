package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrawler_Crawl_MarksVisitedWhenEnqueued(t *testing.T) {
	// This test verifies that URLs are marked as visited when enqueued,
	// not when dequeued. The bug allows the same URL to be added to the queue
	// multiple times before being processed.

	// Create test server
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/page1":
			// Page1 links to shared target
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><a href="` + serverURL + `/shared">Shared</a></body></html>`))
		case "/page2":
			// Page2 also links to same shared target
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><a href="` + serverURL + `/shared">Shared</a></body></html>`))
		case "/shared":
			// Shared target page
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body>Shared content</body></html>`))
		default:
			// Start page links to both page1 and page2
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body>
				<a href="` + serverURL + `/page1">Page 1</a>
				<a href="` + serverURL + `/page2">Page 2</a>
			</body></html>`))
		}
	}))
	serverURL = server.URL
	defer server.Close()

	crawler := NewCrawler(&CrawlerConfig{
		MaxDepth: 3,
		MaxPages: 100,
	})

	scope, err := NewScope(server.URL)
	require.NoError(t, err)

	ctx := context.Background()
	endpoints, err := crawler.Crawl(ctx, server.URL, scope)

	require.NoError(t, err)
	assert.NotEmpty(t, endpoints)

	// Verify /shared appears only once in endpoints
	// With the bug: could appear multiple times if added to queue twice
	// With the fix: appears exactly once
	sharedCount := 0
	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "/shared") {
			sharedCount++
		}
	}
	assert.Equal(t, 1, sharedCount, "/shared should appear exactly once in endpoints")
}

func TestCrawler_Crawl_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><a href="/page2">Link</a></body></html>`))
	}))
	defer server.Close()

	crawler := NewCrawler(&CrawlerConfig{
		MaxDepth: 2,
		MaxPages: 10,
	})

	scope, err := NewScope(server.URL)
	require.NoError(t, err)

	ctx := context.Background()
	endpoints, err := crawler.Crawl(ctx, server.URL, scope)

	require.NoError(t, err)
	assert.NotEmpty(t, endpoints)
}

func TestCrawler_Crawl_RespectsMaxDepth(t *testing.T) {
	depth := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		depth++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><a href="/next">Next</a></body></html>`))
	}))
	defer server.Close()

	crawler := NewCrawler(&CrawlerConfig{
		MaxDepth: 2,
		MaxPages: 100,
	})

	scope, err := NewScope(server.URL)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = crawler.Crawl(ctx, server.URL, scope)

	require.NoError(t, err)
	// Depth should not exceed MaxDepth
	assert.LessOrEqual(t, depth, 2)
}
