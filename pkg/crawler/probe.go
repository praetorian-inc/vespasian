package crawler

import (
	"context"
	"fmt"
	"net/url"

	"github.com/praetorian-inc/vespasian/pkg/probes"
	"github.com/praetorian-inc/vespasian/pkg/registry"
)

func init() {
	probes.Registry.Register("crawler", func(cfg registry.Config) (probes.Probe, error) {
		maxDepth := 3
		maxPages := 100

		if d, ok := cfg["max_depth"].(int); ok {
			maxDepth = d
		}
		if p, ok := cfg["max_pages"].(int); ok {
			maxPages = p
		}

		return NewCrawlerProbe(&CrawlerConfig{
			MaxDepth: maxDepth,
			MaxPages: maxPages,
		}), nil
	})
}

// CrawlerProbe implements probes.Probe for web crawling
type CrawlerProbe struct {
	crawler *Crawler
	config  *CrawlerConfig
}

// NewCrawlerProbe creates a new crawler probe
func NewCrawlerProbe(config *CrawlerConfig) *CrawlerProbe {
	return &CrawlerProbe{
		crawler: NewCrawler(config),
		config:  config,
	}
}

// Name returns the probe name
func (p *CrawlerProbe) Name() string {
	return "crawler"
}

// Category returns the probe category
func (p *CrawlerProbe) Category() probes.ProbeCategory {
	return probes.CategoryHTTP
}

// Priority returns execution priority (higher = earlier)
func (p *CrawlerProbe) Priority() int {
	return 100
}

// Accepts returns true if probe can scan the target
func (p *CrawlerProbe) Accepts(target probes.Target) bool {
	// Only accept HTTP/HTTPS ports
	switch target.Port {
	case 80, 443, 8080, 8443:
		return true
	default:
		return false
	}
}

// Run executes the crawler probe
func (p *CrawlerProbe) Run(ctx context.Context, target probes.Target, opts probes.ProbeOptions) (*probes.ProbeResult, error) {
	// Build base URL
	baseURL, err := buildBaseURL(target)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	// Create scope
	scope, err := NewScope(baseURL)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	// Crawl
	urls, err := p.crawler.Crawl(ctx, baseURL, scope)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	// Convert URLs to endpoints
	endpoints := make([]probes.APIEndpoint, 0, len(urls))
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		endpoints = append(endpoints, probes.APIEndpoint{
			Path:   parsed.Path,
			Method: "GET",
		})
	}

	return &probes.ProbeResult{
		ProbeCategory: p.Category(),
		Success:       true,
		Endpoints:     endpoints,
	}, nil
}

// buildBaseURL constructs base URL from target
func buildBaseURL(target probes.Target) (string, error) {
	// Handle case where Host is already a full URL (from httptest)
	if _, err := url.Parse(target.Host); err == nil && (len(target.Host) > 7 && target.Host[:7] == "http://") || (len(target.Host) > 8 && target.Host[:8] == "https://") {
		return target.Host, nil
	}

	scheme := "http"
	if target.Port == 443 || target.Port == 8443 {
		scheme = "https"
	}

	return fmt.Sprintf("%s://%s", scheme, target.Host), nil
}
