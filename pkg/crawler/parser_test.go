package crawler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_ExtractLinks_Anchors(t *testing.T) {
	html := `
		<html>
		<body>
			<a href="/path1">Link 1</a>
			<a href="http://example.com/path2">Link 2</a>
			<a href="https://example.com/path3">Link 3</a>
		</body>
		</html>
	`

	parser := NewParser()
	links, err := parser.ExtractLinks(html, "http://example.com")

	require.NoError(t, err)
	assert.Len(t, links, 3)
	assert.Contains(t, links, "http://example.com/path1")
	assert.Contains(t, links, "http://example.com/path2")
	assert.Contains(t, links, "https://example.com/path3")
}

func TestParser_ExtractLinks_Images(t *testing.T) {
	html := `
		<html>
		<body>
			<img src="/image1.png">
			<img src="http://example.com/image2.jpg">
		</body>
		</html>
	`

	parser := NewParser()
	links, err := parser.ExtractLinks(html, "http://example.com")

	require.NoError(t, err)
	assert.Len(t, links, 2)
	assert.Contains(t, links, "http://example.com/image1.png")
	assert.Contains(t, links, "http://example.com/image2.jpg")
}

func TestParser_ExtractLinks_Scripts(t *testing.T) {
	html := `
		<html>
		<head>
			<script src="/js/app.js"></script>
			<script src="https://cdn.example.com/lib.js"></script>
		</head>
		</html>
	`

	parser := NewParser()
	links, err := parser.ExtractLinks(html, "http://example.com")

	require.NoError(t, err)
	assert.Len(t, links, 2)
	assert.Contains(t, links, "http://example.com/js/app.js")
	assert.Contains(t, links, "https://cdn.example.com/lib.js")
}

func TestParser_ExtractLinks_Forms(t *testing.T) {
	html := `
		<html>
		<body>
			<form action="/submit">
				<input type="submit">
			</form>
			<form action="http://example.com/process">
				<input type="submit">
			</form>
		</body>
		</html>
	`

	parser := NewParser()
	links, err := parser.ExtractLinks(html, "http://example.com")

	require.NoError(t, err)
	assert.Len(t, links, 2)
	assert.Contains(t, links, "http://example.com/submit")
	assert.Contains(t, links, "http://example.com/process")
}

func TestParser_ExtractLinks_Deduplication(t *testing.T) {
	html := `
		<html>
		<body>
			<a href="/path1">Link 1</a>
			<a href="/path1">Link 1 duplicate</a>
			<a href="/path2">Link 2</a>
		</body>
		</html>
	`

	parser := NewParser()
	links, err := parser.ExtractLinks(html, "http://example.com")

	require.NoError(t, err)
	assert.Len(t, links, 2)
	assert.Contains(t, links, "http://example.com/path1")
	assert.Contains(t, links, "http://example.com/path2")
}

func TestParser_ExtractLinks_IgnoresFragments(t *testing.T) {
	html := `
		<html>
		<body>
			<a href="/path1#section">Link 1</a>
			<a href="/path1">Link 2</a>
		</body>
		</html>
	`

	parser := NewParser()
	links, err := parser.ExtractLinks(html, "http://example.com")

	require.NoError(t, err)
	assert.Len(t, links, 1)
	assert.Contains(t, links, "http://example.com/path1")
}

func TestParser_ExtractLinks_InvalidHTML(t *testing.T) {
	html := `<html><body><a href="/test">`

	parser := NewParser()
	links, err := parser.ExtractLinks(html, "http://example.com")

	require.NoError(t, err)
	assert.Len(t, links, 1)
	assert.Contains(t, links, "http://example.com/test")
}

func TestParser_ExtractLinks_EmptyHref(t *testing.T) {
	html := `
		<html>
		<body>
			<a href="">Empty</a>
			<a href="#">Fragment only</a>
			<a href="/valid">Valid</a>
		</body>
		</html>
	`

	parser := NewParser()
	links, err := parser.ExtractLinks(html, "http://example.com")

	require.NoError(t, err)
	assert.Len(t, links, 1)
	assert.Contains(t, links, "http://example.com/valid")
}
