package js

import (
	"regexp"
	"strings"
)

// Endpoint represents an extracted API endpoint from JavaScript
type Endpoint struct {
	URL        string // The extracted URL/path
	Method     string // GET, POST, etc. if detectable
	Source     string // "fetch", "xhr", "axios", "string_literal"
	Confidence string // "high", "medium", "low"
}

// Parser extracts API endpoints from JavaScript source code
type Parser struct {
	patterns []*regexp.Regexp
}

// NewParser creates a new JS parser with compiled regex patterns
func NewParser() *Parser {
	return &Parser{
		patterns: []*regexp.Regexp{
			// fetch('/api/users') or fetch("/api/users") or fetch(`/api/users`)
			regexp.MustCompile(`fetch\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]`),
			// fetch('/api/users', {method: 'POST'})
			regexp.MustCompile(`fetch\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]\s*,\s*\{[^}]*method\s*:\s*['"](\w+)['"]`),
			// xhr.open('GET', '/api/data')
			regexp.MustCompile(`\.open\s*\(\s*['"](\w+)['"]\s*,\s*['"\x60]([^'"\x60]+)['"\x60]`),
			// axios.get('/api/endpoint')
			regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]`),
			// String literals with /api/ pattern
			regexp.MustCompile(`['"\x60](/api/[^'"\x60\s]+)['"\x60]`),
		},
	}
}

// ExtractEndpoints extracts all API endpoints from JavaScript source
func (p *Parser) ExtractEndpoints(jsSource string) []Endpoint {
	type match struct {
		pos      int
		endpoint Endpoint
	}
	var matches []match
	seen := make(map[string]bool)      // Track exact matches
	seenURLs := make(map[string]bool)  // Track URLs to avoid string_literal duplicates

	// Extract fetch calls with method
	fetchWithMethodRe := regexp.MustCompile(`fetch\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]\s*,\s*\{[^}]*method\s*:\s*['"](\w+)['"]`)
	allMatches := fetchWithMethodRe.FindAllStringSubmatchIndex(jsSource, -1)
	for _, m := range allMatches {
		url := jsSource[m[2]:m[3]]
		method := strings.ToUpper(jsSource[m[4]:m[5]])
		key := url + "|" + method
		if !seen[key] {
			matches = append(matches, match{
				pos: m[0],
				endpoint: Endpoint{
					URL:        url,
					Method:     method,
					Source:     "fetch",
					Confidence: "high",
				},
			})
			seen[key] = true
			seenURLs[url] = true
		}
	}

	// Extract basic fetch calls (default GET)
	// Match fetch with just URL (no second parameter with options)
	fetchRe := regexp.MustCompile(`fetch\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]\s*\)`)
	allMatches = fetchRe.FindAllStringSubmatchIndex(jsSource, -1)
	for _, m := range allMatches {
		url := jsSource[m[2]:m[3]]
		// Check if it's a template literal with ${...}
		isTemplate := strings.Contains(url, "${")
		method := "GET"
		confidence := "high"
		originalURL := url
		if isTemplate {
			// Extract base path (remove template variables)
			url = regexp.MustCompile(`\$\{[^}]+\}`).ReplaceAllString(url, "")
			confidence = "medium"
			seenURLs[originalURL] = true  // Mark original to avoid string_literal match
		}
		key := url + "|" + method
		if !seen[key] {
			matches = append(matches, match{
				pos: m[0],
				endpoint: Endpoint{
					URL:        url,
					Method:     method,
					Source:     "fetch",
					Confidence: confidence,
				},
			})
			seen[key] = true
			seenURLs[url] = true
		}
	}

	// Extract XMLHttpRequest .open() calls
	xhrRe := regexp.MustCompile(`\.open\s*\(\s*['"](\w+)['"]\s*,\s*['"\x60]([^'"\x60]+)['"\x60]`)
	allMatches = xhrRe.FindAllStringSubmatchIndex(jsSource, -1)
	for _, m := range allMatches {
		method := strings.ToUpper(jsSource[m[2]:m[3]])
		url := jsSource[m[4]:m[5]]
		key := url + "|" + method
		if !seen[key] {
			matches = append(matches, match{
				pos: m[0],
				endpoint: Endpoint{
					URL:        url,
					Method:     method,
					Source:     "xhr",
					Confidence: "high",
				},
			})
			seen[key] = true
			seenURLs[url] = true
		}
	}

	// Extract axios calls
	axiosRe := regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]`)
	allMatches = axiosRe.FindAllStringSubmatchIndex(jsSource, -1)
	for _, m := range allMatches {
		method := strings.ToUpper(jsSource[m[2]:m[3]])
		url := jsSource[m[4]:m[5]]
		key := url + "|" + method
		if !seen[key] {
			matches = append(matches, match{
				pos: m[0],
				endpoint: Endpoint{
					URL:        url,
					Method:     method,
					Source:     "axios",
					Confidence: "high",
				},
			})
			seen[key] = true
			seenURLs[url] = true
		}
	}

	// Extract string literals with /api/ pattern (low confidence)
	// Only add if not already found by high-confidence patterns
	apiLiteralRe := regexp.MustCompile(`['"](/api/[^'"\s]+)['"]`)
	allMatches = apiLiteralRe.FindAllStringSubmatchIndex(jsSource, -1)
	for _, m := range allMatches {
		url := jsSource[m[2]:m[3]]
		// Skip if already seen as high-confidence pattern
		if seenURLs[url] {
			continue
		}
		key := url + "|"
		if !seen[key] {
			matches = append(matches, match{
				pos: m[0],
				endpoint: Endpoint{
					URL:        url,
					Method:     "",
					Source:     "string_literal",
					Confidence: "low",
				},
			})
			seen[key] = true
		}
	}

	// Sort by position in source to maintain order
	// Use simple bubble sort for small arrays
	for i := 0; i < len(matches); i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[j].pos < matches[i].pos {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}

	// Extract endpoints in order
	var endpoints []Endpoint
	for _, m := range matches {
		endpoints = append(endpoints, m.endpoint)
	}

	return endpoints
}
