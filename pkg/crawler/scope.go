package crawler

import (
	"net/url"
	"strings"
)

// Scope defines crawling boundaries
type Scope struct {
	baseURL *url.URL
}

// NewScope creates a new scope from base URL
func NewScope(baseURL string) (*Scope, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	return &Scope{
		baseURL: parsed,
	}, nil
}

// InScope returns true if URL is within crawling scope
func (s *Scope) InScope(targetURL string) bool {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	// Must be same scheme (http/https)
	if parsed.Scheme != s.baseURL.Scheme {
		return false
	}

	// Must be same host
	if parsed.Host != s.baseURL.Host {
		return false
	}

	// Must be under base path
	if !strings.HasPrefix(parsed.Path, s.baseURL.Path) {
		return false
	}

	return true
}
