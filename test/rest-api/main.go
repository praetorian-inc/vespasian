// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main provides a simple REST API server for live testing of vespasian.
// It exposes a known set of endpoints so that generated OpenAPI specs can be
// validated against expected paths and methods.
package main

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

// User represents a user resource.
type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Product represents a product resource.
type Product struct {
	ID    int     `json:"id"`
	Name  string  `json:"name"`
	Price float64 `json:"price"`
}

// Order represents an order resource.
type Order struct {
	ID        int   `json:"id"`
	UserID    int   `json:"user_id"`
	ProductID int   `json:"product_id"`
	Quantity  int   `json:"quantity"`
}

// EmailUpdate represents a request to update a user's email.
type EmailUpdate struct {
	Email string `json:"email"`
}

var (
	mu sync.Mutex

	users = []User{
		{ID: 1, Name: "Alice", Email: "alice@example.com"},
		{ID: 2, Name: "Bob", Email: "bob@example.com"},
		{ID: 3, Name: "Charlie", Email: "charlie@example.com"},
	}
	products = []Product{
		{ID: 1, Name: "Widget", Price: 9.99},
		{ID: 2, Name: "Gadget", Price: 24.99},
		{ID: 3, Name: "Gizmo", Price: 14.99},
	}
	orders = []Order{
		{ID: 1, UserID: 1, ProductID: 2, Quantity: 1},
		{ID: 2, UserID: 2, ProductID: 1, Quantity: 3},
	}
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, users)
	case http.MethodPost:
		var u User
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		u.ID = len(users) + 1
		users = append(users, u)
		writeJSON(w, http.StatusCreated, u)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func handleUserByID(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, PUT, PATCH, DELETE, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Extract ID from path: /api/users/{id} or /api/users/{id}/email-address
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	// Check for nested resources
	if len(parts) == 2 && parts[1] == "email-address" {
		handleUserEmail(w, r)
		return
	}
	if len(parts) >= 2 && parts[1] == "orders" {
		handleUserOrders(w, r)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, users[0])
	case http.MethodPut:
		var u User
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		writeJSON(w, http.StatusOK, u)
	case http.MethodPatch:
		var patch map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		writeJSON(w, http.StatusOK, users[0])
	case http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func handleUserEmail(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, PUT, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, EmailUpdate{Email: users[0].Email})
	case http.MethodPut:
		var eu EmailUpdate
		if err := json.NewDecoder(r.Body).Decode(&eu); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		writeJSON(w, http.StatusOK, eu)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func handleProducts(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	mu.Lock()
	defer mu.Unlock()
	writeJSON(w, http.StatusOK, products)
}

func handleProductByID(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	mu.Lock()
	defer mu.Unlock()
	writeJSON(w, http.StatusOK, products[0])
}

func handleOrders(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, orders)
	case http.MethodPost:
		var o Order
		if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		o.ID = len(orders) + 1
		orders = append(orders, o)
		writeJSON(w, http.StatusCreated, o)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func handleOrderByID(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	mu.Lock()
	defer mu.Unlock()
	writeJSON(w, http.StatusOK, orders[0])
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Edge case endpoints ─────────────────────────────────────

// handleLargeResponse returns a large JSON array (~100KB) to test body truncation.
func handleLargeResponse(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	items := make([]map[string]interface{}, 500)
	for i := range items {
		items[i] = map[string]interface{}{
			"id":          i + 1,
			"name":        fmt.Sprintf("Item %d with a longer description to increase payload size", i+1),
			"value":       float64(i) * 1.23,
			"active":      i%2 == 0,
			"tags":        []string{"tag-a", "tag-b", "tag-c"},
			"description": "This is a repeated description field to bulk up the response payload for testing large body handling.",
		}
	}
	writeJSON(w, http.StatusOK, items)
}

// handleSearch accepts query params with special characters.
// Example: /api/search?q=hello+world&filter=name:alice&page=1
func handleSearch(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	q := r.URL.Query()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"query":   q.Get("q"),
		"filter":  q.Get("filter"),
		"page":    q.Get("page"),
		"results": []map[string]string{{"id": "1", "name": "Result 1"}},
	})
}

// handleSpecialChars tests paths with URL-encoded special characters.
// Serves /api/categories/{name} where name can contain spaces, unicode, etc.
func handleSpecialChars(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/categories/")
	writeJSON(w, http.StatusOK, map[string]string{
		"category": name,
		"status":   "found",
	})
}

// handleRedirect sends a 301 redirect to /api/users.
func handleRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/api/users", http.StatusMovedPermanently)
}

// handleRedirectRelative sends a 302 redirect to a relative path.
func handleRedirectRelative(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/api/products", http.StatusFound)
}

// handleError404 always returns 404 with a JSON error body.
func handleError404(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotFound, map[string]string{
		"error":   "not_found",
		"message": "The requested resource does not exist",
	})
}

// handleError500 always returns 500 with a JSON error body.
func handleError500(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{
		"error":   "internal_error",
		"message": "Something went wrong",
	})
}

// handleBinaryResponse returns raw binary (PNG header bytes) to test non-UTF8 handling.
func handleBinaryResponse(w http.ResponseWriter, _ *http.Request) {
	// 1x1 transparent PNG
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	// Minimal PNG: 8-byte header + minimal IHDR + IEND
	data := make([]byte, 128)
	copy(data, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	_, _ = w.Write(data)
}

// handleMixedContent returns JSON with a field containing base64 binary data.
func handleMixedContent(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	randomBytes := make([]byte, 64)
	_, _ = rand.Read(randomBytes)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":     1,
		"name":   "binary-test",
		"random": randomBytes,
	})
}

// handleEmptyResponse returns 204 No Content with no body.
func handleEmptyResponse(w http.ResponseWriter, _ *http.Request) {
	setCORSHeaders(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleSlowResponse waits briefly before responding (tests timeout edge cases).
func handleSlowResponse(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "delayed"})
}

// handleTrailingSlash tests path normalization with trailing slashes.
func handleTrailingSlash(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	writeJSON(w, http.StatusOK, map[string]string{"path": r.URL.Path, "normalized": "true"})
}

// ── Crawl edge case endpoints ───────────────────────────────

// handleMismatchedContentType returns JSON body with text/html content-type.
func handleMismatchedContentType(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "mismatched"})
}

// handleAuthRequired returns 401 unless Authorization header is present.
func handleAuthRequired(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Header.Get("Authorization") == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="test"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "authenticated", "user": "test"})
}

// handleDeepLinks creates a chain of pages, each linking to the next deeper level.
// /api/deep/1 → /api/deep/2 → ... → /api/deep/6
func handleDeepLinks(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	level := strings.TrimPrefix(r.URL.Path, "/api/deep/")
	var depth int
	fmt.Sscanf(level, "%d", &depth)
	if depth <= 0 {
		depth = 1
	}

	if depth >= 6 {
		writeJSON(w, http.StatusOK, map[string]string{"level": level, "status": "bottom"})
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html><body>
<h1>Level %d</h1>
<a href="/api/deep/%d">Go deeper</a>
<a href="/api/deep/data/%d">Data at level %d</a>
</body></html>`, depth, depth+1, depth, depth)
}

// handleDeepData returns JSON data at a specific depth level.
func handleDeepData(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	level := strings.TrimPrefix(r.URL.Path, "/api/deep/data/")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"level": level,
		"data":  fmt.Sprintf("payload-at-depth-%s", level),
	})
}

// handleManyLinks returns a page with many links to test max-pages.
func handleManyLinks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><h1>Many Links</h1><ul>")
	for i := 1; i <= 20; i++ {
		fmt.Fprintf(w, `<li><a href="/api/items/%d">Item %d</a></li>`, i, i)
	}
	fmt.Fprint(w, "</ul></body></html>")
}

// handleItem returns a single item by numeric or UUID ID.
func handleItem(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	id := strings.TrimPrefix(r.URL.Path, "/api/items/")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "type": "item"})
}

// handleLoopPage returns a page that links back to itself (infinite loop test).
func handleLoopPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<html><body>
<h1>Loop Page</h1>
<a href="/api/loop">Self link</a>
<a href="/api/loop?ref=1">Self with param 1</a>
<a href="/api/loop?ref=2">Self with param 2</a>
<a href="/api/loop-b">Partner loop</a>
</body></html>`)
}

// handleLoopPageB links back to handleLoopPage.
func handleLoopPageB(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<html><body>
<h1>Loop Page B</h1>
<a href="/api/loop">Back to loop A</a>
<a href="/api/loop-b">Self link</a>
</body></html>`)
}

// handleGzipResponse returns gzip-compressed JSON.
func handleGzipResponse(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		writeJSON(w, http.StatusOK, map[string]string{"compressed": "false"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	gz := gzip.NewWriter(w)
	_ = json.NewEncoder(gz).Encode(map[string]string{"compressed": "true", "data": "gzip-test-payload"})
	_ = gz.Close()
}

// ── Classifier edge case endpoints ──────────────────────────

// handleRSSFeed returns an RSS feed (XML that looks like SOAP but isn't).
func handleRSSFeed(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/rss+xml")
	fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <link>http://localhost:8990</link>
    <item><title>Item 1</title><description>Test item</description></item>
    <item><title>Item 2</title><description>Another item</description></item>
  </channel>
</rss>`)
}

// handleV1Resources and handleV2Resources test API version path heuristics.
func handleV1Resources(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version": "v1",
		"items":   []map[string]string{{"id": "1", "name": "legacy-item"}},
	})
}

func handleV2Resources(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version": "v2",
		"data":    []map[string]interface{}{{"id": 1, "name": "modern-item", "metadata": map[string]string{"format": "v2"}}},
	})
}

// handleGraphQL accepts POST with GraphQL query body.
func handleGraphQL(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodGet {
		// GraphiQL-style HTML page
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>GraphQL Endpoint</h1><p>POST a query to this endpoint.</p></body></html>`)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"users": []map[string]string{
				{"id": "1", "name": "Alice"},
				{"id": "2", "name": "Bob"},
			},
		},
	})
}

// handleHTMLError returns text/html content-type but serves an HTML error page
// from a path that looks like an API endpoint.
func handleHTMLError(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprint(w, `<html><head><title>502 Bad Gateway</title></head>
<body><h1>502 Bad Gateway</h1><p>The upstream server returned an error.</p></body></html>`)
}

// ── Spec generation edge case endpoints ─────────────────────

// handleUserOrders serves /api/users/{id}/orders and /api/users/{id}/orders/{orderId}
// to test multi-parameter path normalization.
func handleUserOrders(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	// Path: /api/users/{id}/orders or /api/users/{id}/orders/{orderId}
	path := strings.TrimPrefix(r.URL.Path, "/api/users/")
	parts := strings.Split(path, "/")
	// parts: ["{id}", "orders"] or ["{id}", "orders", "{orderId}"]
	if len(parts) >= 3 {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"order_id":   parts[2],
			"user_id":    parts[0],
			"product":    "Widget",
			"quantity":   2,
			"total":      19.98,
		})
	} else {
		writeJSON(w, http.StatusOK, []map[string]interface{}{
			{"order_id": "101", "product": "Widget", "quantity": 2},
			{"order_id": "102", "product": "Gadget", "quantity": 1},
		})
	}
}

// handleUUIDItem serves /api/assets/{uuid} to test UUID path parameter detection.
func handleUUIDItem(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	id := strings.TrimPrefix(r.URL.Path, "/api/assets/")
	writeJSON(w, http.StatusOK, map[string]string{
		"id":   id,
		"type": "asset",
		"name": "Test Asset",
	})
}

// handleEmptyOK returns 200 with application/json content-type but empty body.
func handleEmptyOK(w http.ResponseWriter, _ *http.Request) {
	setCORSHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Vespasian Test REST API</title></head>
<body>
<h1>Vespasian Test REST API</h1>
<h2>API Endpoints</h2>
<ul>
  <li><a href="/api/health">GET /api/health</a></li>
  <li><a href="/api/users">GET /api/users</a></li>
  <li><a href="/api/users/1">GET /api/users/1</a></li>
  <li><a href="/api/users/1/email-address">GET /api/users/1/email-address</a></li>
  <li><a href="/api/products">GET /api/products</a></li>
  <li><a href="/api/products/1">GET /api/products/1</a></li>
  <li><a href="/api/orders">GET /api/orders</a></li>
  <li><a href="/api/orders/1">GET /api/orders/1</a></li>
</ul>
<p>Edge case endpoints are available but not linked here to avoid polluting the crawl.</p>
<h2>Write Endpoints (POST/PUT/PATCH/DELETE)</h2>
<ul>
  <li>POST /api/users - Create user</li>
  <li>PUT /api/users/{id} - Update user</li>
  <li>PATCH /api/users/{id} - Partial update user</li>
  <li>DELETE /api/users/{id} - Delete user</li>
  <li>PUT /api/users/{id}/email-address - Update email</li>
  <li>POST /api/orders - Create order</li>
</ul>
</body>
</html>`)
}

func handleEdgeCaseIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Edge Case Endpoints</title></head>
<body>
<h1>Edge Case Endpoints</h1>
<h2>Response Types</h2>
<ul>
  <li><a href="/api/large">GET /api/large</a> - Large response (~100KB)</li>
  <li><a href="/api/binary">GET /api/binary</a> - Binary (PNG) response</li>
  <li><a href="/api/mixed">GET /api/mixed</a> - JSON with binary field</li>
  <li><a href="/api/empty">GET /api/empty</a> - 204 No Content</li>
  <li><a href="/api/empty-ok">GET /api/empty-ok</a> - 200 OK with empty body</li>
  <li><a href="/api/gzip">GET /api/gzip</a> - Gzip-compressed JSON</li>
  <li><a href="/api/slow">GET /api/slow</a> - Slow response</li>
  <li><a href="/api/error/404">GET /api/error/404</a> - JSON 404 error</li>
  <li><a href="/api/error/500">GET /api/error/500</a> - JSON 500 error</li>
  <li><a href="/api/mismatched-ct">GET /api/mismatched-ct</a> - JSON body with text/html content-type</li>
  <li><a href="/api/html-error">GET /api/html-error</a> - HTML error from API path</li>
</ul>
<h2>URL Handling</h2>
<ul>
  <li><a href="/api/search?q=hello+world&filter=name%3Aalice&page=1">GET /api/search?q=hello+world&amp;filter=name:alice</a> - Special query params</li>
  <li><a href="/api/categories/electronics%20%26%20gadgets">GET /api/categories/electronics &amp; gadgets</a> - URL-encoded path</li>
  <li><a href="/api/redirect">GET /api/redirect</a> - 301 redirect</li>
  <li><a href="/api/redirect-relative">GET /api/redirect-relative</a> - 302 redirect</li>
  <li><a href="/api/trailing/">GET /api/trailing/</a> - Trailing slash</li>
  <li><a href="/api/auth-required">GET /api/auth-required</a> - 401 without auth header</li>
</ul>
<h2>Crawl Behavior</h2>
<ul>
  <li><a href="/api/deep/1">GET /api/deep/1</a> - Deep link chain (6 levels)</li>
  <li><a href="/api/many-links">GET /api/many-links</a> - Page with 20 links</li>
  <li><a href="/api/loop">GET /api/loop</a> - Self-referencing page</li>
</ul>
<h2>Classifier</h2>
<ul>
  <li><a href="/feed.xml">GET /feed.xml</a> - RSS feed (XML, not SOAP)</li>
  <li><a href="/api/v1/resources">GET /api/v1/resources</a> - API v1 path</li>
  <li><a href="/api/v2/resources">GET /api/v2/resources</a> - API v2 path</li>
  <li><a href="/graphql">GET /graphql</a> - GraphQL endpoint</li>
</ul>
<h2>Spec Generation</h2>
<ul>
  <li><a href="/api/users/1/orders">GET /api/users/1/orders</a> - Multi-param: user orders</li>
  <li><a href="/api/users/1/orders/101">GET /api/users/1/orders/101</a> - Multi-param: specific order</li>
  <li><a href="/api/users/2/orders/102">GET /api/users/2/orders/102</a> - Multi-param: different IDs</li>
  <li><a href="/api/assets/550e8400-e29b-41d4-a716-446655440000">GET /api/assets/{uuid}</a> - UUID path param</li>
  <li><a href="/api/assets/6ba7b810-9dad-11d1-80b4-00c04fd430c8">GET /api/assets/{uuid} (2)</a> - Second UUID</li>
  <li><a href="/api/items/42">GET /api/items/42</a> - Numeric ID</li>
  <li><a href="/api/items/99">GET /api/items/99</a> - Numeric ID (2)</li>
</ul>
</body>
</html>`)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8990"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/edge-cases", handleEdgeCaseIndex)
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/users", handleUsers)
	mux.HandleFunc("/api/users/", handleUserByID)
	mux.HandleFunc("/api/products", handleProducts)
	mux.HandleFunc("/api/products/", handleProductByID)
	mux.HandleFunc("/api/orders", handleOrders)
	mux.HandleFunc("/api/orders/", handleOrderByID)

	// Edge case: response types
	mux.HandleFunc("/api/large", handleLargeResponse)
	mux.HandleFunc("/api/binary", handleBinaryResponse)
	mux.HandleFunc("/api/mixed", handleMixedContent)
	mux.HandleFunc("/api/empty", handleEmptyResponse)
	mux.HandleFunc("/api/empty-ok", handleEmptyOK)
	mux.HandleFunc("/api/gzip", handleGzipResponse)
	mux.HandleFunc("/api/slow", handleSlowResponse)
	mux.HandleFunc("/api/error/404", handleError404)
	mux.HandleFunc("/api/error/500", handleError500)
	mux.HandleFunc("/api/mismatched-ct", handleMismatchedContentType)
	mux.HandleFunc("/api/html-error", handleHTMLError)

	// Edge case: URL handling
	mux.HandleFunc("/api/search", handleSearch)
	mux.HandleFunc("/api/categories/", handleSpecialChars)
	mux.HandleFunc("/api/redirect", handleRedirect)
	mux.HandleFunc("/api/redirect-relative", handleRedirectRelative)
	mux.HandleFunc("/api/trailing/", handleTrailingSlash)
	mux.HandleFunc("/api/auth-required", handleAuthRequired)

	// Edge case: crawl behavior
	mux.HandleFunc("/api/deep/data/", handleDeepData)
	mux.HandleFunc("/api/deep/", handleDeepLinks)
	mux.HandleFunc("/api/many-links", handleManyLinks)
	mux.HandleFunc("/api/items/", handleItem)
	mux.HandleFunc("/api/loop", handleLoopPage)
	mux.HandleFunc("/api/loop-b", handleLoopPageB)

	// Edge case: classifier
	mux.HandleFunc("/feed.xml", handleRSSFeed)
	mux.HandleFunc("/api/v1/resources", handleV1Resources)
	mux.HandleFunc("/api/v2/resources", handleV2Resources)
	mux.HandleFunc("/graphql", handleGraphQL)

	// Edge case: spec generation
	mux.HandleFunc("/api/assets/", handleUUIDItem)
	// /api/users/{id}/orders is routed via handleUserByID

	addr := ":" + port
	log.Printf("rest-api listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
