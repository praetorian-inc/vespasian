package crawler

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Parser extracts links from HTML
type Parser struct{}

// NewParser creates a new HTML parser
func NewParser() *Parser {
	return &Parser{}
}

// ExtractLinks extracts all links from HTML content
func (p *Parser) ExtractLinks(htmlContent, baseURL string) ([]string, error) {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("parse HTML: %w", err)
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}

	seen := make(map[string]bool)
	var links []string

	var extractNode func(*html.Node)
	extractNode = func(n *html.Node) {
		if n.Type == html.ElementNode {
			var link string

			switch n.Data {
			case "a":
				link = getAttr(n, "href")
			case "img", "script":
				link = getAttr(n, "src")
			case "form":
				link = getAttr(n, "action")
			}

			if link != "" && !strings.HasPrefix(link, "#") && link != "#" {
				// Parse and resolve relative URLs
				resolved, err := resolveURL(base, link)
				if err == nil && !seen[resolved] {
					seen[resolved] = true
					links = append(links, resolved)
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractNode(c)
		}
	}

	extractNode(doc)
	return links, nil
}

// getAttr gets attribute value from node
func getAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

// resolveURL resolves a relative URL against a base URL and removes fragments
func resolveURL(base *url.URL, href string) (string, error) {
	if href == "" {
		return "", fmt.Errorf("empty href")
	}

	ref, err := url.Parse(href)
	if err != nil {
		return "", err
	}

	// Remove fragment
	ref.Fragment = ""

	resolved := base.ResolveReference(ref)
	return resolved.String(), nil
}
