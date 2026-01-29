package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ClientConfig configures the HTTP client
type ClientConfig struct {
	Timeout    time.Duration
	MaxRetries int
	UserAgent  string
}

// Client wraps http.Client with retries and rate limiting
type Client struct {
	httpClient *http.Client
	maxRetries int
	userAgent  string
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// NewClient creates a new HTTP client
func NewClient(config *ClientConfig) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		maxRetries: config.MaxRetries,
		userAgent:  config.UserAgent,
	}
}

// Get performs HTTP GET request with retries
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	var lastErr error

	for attempt := 0; attempt < c.maxRetries; attempt++ {
		// Check context before each attempt
		if ctx.Err() != nil {
			return nil, fmt.Errorf("context canceled: %w", ctx.Err())
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("User-Agent", c.userAgent)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < c.maxRetries-1 {
				time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("request failed after %d attempts: %w", c.maxRetries, lastErr)
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close() // Close immediately after reading

		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}

		// Retry on 5xx errors
		if resp.StatusCode >= 500 && attempt < c.maxRetries-1 {
			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
			time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
			continue
		}

		return &Response{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       body,
		}, nil
	}

	return nil, lastErr
}
