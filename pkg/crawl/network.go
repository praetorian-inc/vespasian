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

package crawl

import (
	"encoding/base64"
	"net/url"
	"strings"
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// pendingRequest tracks a network request that has been sent but whose
// response has not yet been fully received.
type pendingRequest struct {
	method  string
	url     string
	headers map[string]string
	body    string

	// Filled by responseReceived:
	statusCode  int
	respHeaders map[string]string
	contentType string

	// Filled by loadingFinished → getResponseBody:
	respBody []byte
	complete bool
}

// pageNetworkCapture passively captures all network requests and responses on
// a single page via CDP Network domain events. It correlates request/response
// pairs by request ID and produces ObservedRequest values.
type pageNetworkCapture struct {
	mu      sync.Mutex
	pending map[proto.NetworkRequestID]*pendingRequest
	pageURL string
	page    *rod.Page
}

// newPageNetworkCapture creates a capture session and wires up CDP event
// listeners on the given page. The caller must call wait() (returned by
// setupListeners) after page navigation completes to ensure all events are
// processed.
func newPageNetworkCapture(page *rod.Page, pageURL string) (*pageNetworkCapture, func()) {
	c := &pageNetworkCapture{
		pending: make(map[proto.NetworkRequestID]*pendingRequest),
		pageURL: pageURL,
		page:    page,
	}
	wait := c.setupListeners(page)
	return c, wait
}

// setupListeners registers CDP event handlers and returns a wait function.
// The wait function blocks until all registered events resolve. Callers
// should invoke it in a goroutine; it runs for the lifetime of the page.
func (c *pageNetworkCapture) setupListeners(page *rod.Page) func() {
	return page.EachEvent(
		func(e *proto.NetworkRequestWillBeSent) {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.pending[e.RequestID] = &pendingRequest{
				method:  e.Request.Method,
				url:     e.Request.URL,
				headers: flattenNetworkHeaders(e.Request.Headers),
				body:    e.Request.PostData,
			}
		},
		func(e *proto.NetworkResponseReceived) {
			c.mu.Lock()
			defer c.mu.Unlock()
			req, ok := c.pending[e.RequestID]
			if !ok {
				return
			}
			req.statusCode = e.Response.Status
			req.respHeaders = flattenNetworkHeaders(e.Response.Headers)
			req.contentType = e.Response.MIMEType
		},
		func(e *proto.NetworkLoadingFinished) {
			c.mu.Lock()
			req, ok := c.pending[e.RequestID]
			if !ok || req.complete {
				// Not found or already finalized — skip to prevent
				// duplicate writes from replayed CDP events (H-1 fix).
				c.mu.Unlock()
				return
			}
			// Mark complete under lock before releasing for the blocking
			// CDP call. This ensures no other handler can finalize this
			// request concurrently (H-1 fix).
			req.complete = true
			c.mu.Unlock()

			// Fetch response body outside the lock — this is a CDP call
			// that can block. The body may be unavailable (e.g., for
			// redirects or cached responses); that's fine.
			body, err := proto.NetworkGetResponseBody{RequestID: e.RequestID}.Call(page)
			if err == nil && body != nil {
				var bodyBytes []byte
				if body.Base64Encoded {
					decoded, decodeErr := base64.StdEncoding.DecodeString(body.Body)
					if decodeErr == nil {
						bodyBytes = decoded
					}
				} else {
					bodyBytes = []byte(body.Body)
				}
				// Truncate at collection time to bound memory usage.
				// Without this, a hostile page generating many large XHR
				// responses could exhaust memory (H-3 fix).
				bodyBytes = truncateBody(bodyBytes)

				c.mu.Lock()
				req.respBody = bodyBytes
				c.mu.Unlock()
			}
		},
	)
}

// Results returns all captured network exchanges as ObservedRequest values.
// Call this after navigation and DOM stability wait are complete.
func (c *pageNetworkCapture) Results() []ObservedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	results := make([]ObservedRequest, 0, len(c.pending))
	for _, req := range c.pending {
		results = append(results, mapNetworkToObservedRequest(req, c.pageURL))
	}
	return results
}

// mapNetworkToObservedRequest converts a captured network exchange to an
// ObservedRequest, applying body truncation and extracting query parameters.
func mapNetworkToObservedRequest(req *pendingRequest, pageURL string) ObservedRequest {
	obs := ObservedRequest{
		Method:  req.method,
		URL:     req.url,
		Headers: req.headers,
		Body:    truncateBody([]byte(req.body)),
		Source:  "browser",
		PageURL: pageURL,
		Response: ObservedResponse{
			StatusCode:  req.statusCode,
			Headers:     req.respHeaders,
			ContentType: req.contentType,
			Body:        truncateBody(req.respBody),
		},
	}

	if obs.Method == "" {
		obs.Method = "GET"
	}

	// Parse query parameters from URL.
	if obs.URL != "" {
		if u, err := url.Parse(obs.URL); err == nil {
			obs.QueryParams = make(map[string]string)
			for key, values := range u.Query() {
				if len(values) > 0 {
					obs.QueryParams[key] = values[0]
				}
			}
		}
	}

	return obs
}

// truncateBody returns body truncated to MaxResponseBodySize.
func truncateBody(body []byte) []byte {
	if len(body) > MaxResponseBodySize {
		return body[:MaxResponseBodySize]
	}
	return body
}

// flattenNetworkHeaders converts CDP NetworkHeaders (map[string]gson.JSON) to
// a simple map[string]string, lowercasing header names for consistency.
func flattenNetworkHeaders(headers proto.NetworkHeaders) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	result := make(map[string]string, len(headers))
	for k, v := range headers {
		result[strings.ToLower(k)] = v.String()
	}
	return result
}
