package crawler

import (
	"context"
	"sync"

	vhttp "github.com/praetorian-inc/vespasian/pkg/http"
)

// CrawlerConfig configures the crawler
type CrawlerConfig struct {
	MaxDepth int
	MaxPages int
}

// Crawler orchestrates web crawling with BFS
type Crawler struct {
	client  *vhttp.Client
	parser  *Parser
	config  *CrawlerConfig
	visited map[string]bool
	mu      sync.Mutex
}

// NewCrawler creates a new crawler
func NewCrawler(config *CrawlerConfig) *Crawler {
	return &Crawler{
		client: vhttp.NewClient(&vhttp.ClientConfig{
			Timeout:    5000000000, // 5 seconds
			MaxRetries: 3,
			UserAgent:  "vespasian-crawler",
		}),
		parser:  NewParser(),
		config:  config,
		visited: make(map[string]bool),
	}
}

// Crawl performs BFS crawl starting from startURL
func (c *Crawler) Crawl(ctx context.Context, startURL string, scope *Scope) ([]string, error) {
	// Mark start URL as visited when adding to queue
	c.visited[startURL] = true

	queue := []struct {
		url   string
		depth int
	}{{startURL, 0}}

	var endpoints []string

	for len(queue) > 0 && len(endpoints) < c.config.MaxPages {
		// Dequeue
		current := queue[0]
		queue = queue[1:]


		// Check depth limit
		if current.depth >= c.config.MaxDepth {
			continue
		}

		// Check context
		if ctx.Err() != nil {
			return endpoints, ctx.Err()
		}

		// Fetch page
		resp, err := c.client.Get(ctx, current.url)
		if err != nil {
			continue // Skip failed requests
		}

		// Add to endpoints
		endpoints = append(endpoints, current.url)

		// Extract links
		links, err := c.parser.ExtractLinks(string(resp.Body), current.url)
		if err != nil {
			continue // Skip parse errors
		}

		// Add in-scope links to queue
		for _, link := range links {
			if scope.InScope(link) {
				c.mu.Lock()
				if !c.visited[link] {
					// Mark as visited when adding to queue (not when dequeuing)
					c.visited[link] = true
					queue = append(queue, struct {
						url   string
						depth int
					}{link, current.depth + 1})
				}
				c.mu.Unlock()
			}
		}
	}

	return endpoints, nil
}

// IsVisited returns true if URL has been visited
func (c *Crawler) IsVisited(url string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.visited[url]
}

// VisitedCount returns number of visited URLs
func (c *Crawler) VisitedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.visited)
}
