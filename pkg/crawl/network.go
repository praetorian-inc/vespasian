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

// pendingRequest is a sent request whose response is still arriving.
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

// pageNetworkCapture correlates CDP Network events by request ID into
// ObservedRequest values.
type pageNetworkCapture struct {
	mu      sync.Mutex
	pending map[proto.NetworkRequestID]*pendingRequest
	pageURL string
	page    *rod.Page
}

// newPageNetworkCapture wires up the CDP listeners. The caller must run the
// returned wait function so events are processed.
func newPageNetworkCapture(page *rod.Page, pageURL string) (*pageNetworkCapture, func()) {
	c := &pageNetworkCapture{
		pending: make(map[proto.NetworkRequestID]*pendingRequest),
		pageURL: pageURL,
		page:    page,
	}
	wait := c.setupListeners(page)
	return c, wait
}

// setupListeners returns a function that blocks for the lifetime of the page; run
// it in a goroutine.
func (c *pageNetworkCapture) setupListeners(page *rod.Page) func() {
	return page.EachEvent(
		func(e *proto.NetworkRequestWillBeSent) {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.pending[e.RequestID] = &pendingRequest{
				method:  e.Request.Method,
				url:     e.Request.URL,
				headers: flattenNetworkHeaders(e.Request.Headers),
				body:    string(truncateBody([]byte(e.Request.PostData))),
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
			// CDP replays events, so an already-finalized request must be skipped or
			// it is written twice.
			if !ok || req.complete {
				c.mu.Unlock()
				return
			}
			// Set while still holding the lock, before releasing it for the blocking
			// CDP call below, so no other handler can finalize this concurrently.
			req.complete = true
			c.mu.Unlock()

			// Outside the lock: this CDP call blocks. An unavailable body (redirect,
			// cached response) is fine.
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
				// At collection time, not at use: a hostile page generating many large
				// XHR responses would exhaust memory before anything downstream
				// could cap it.
				bodyBytes = truncateBody(bodyBytes)

				c.mu.Lock()
				req.respBody = bodyBytes
				c.mu.Unlock()
			}
		},
	)
}

// Results is valid once navigation and the stability wait are complete.
func (c *pageNetworkCapture) Results() []ObservedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	results := make([]ObservedRequest, 0, len(c.pending))
	for _, req := range c.pending {
		results = append(results, mapNetworkToObservedRequest(req, c.pageURL))
	}
	return results
}

// mapNetworkToObservedRequest converts one exchange. Bodies were already
// truncated at collection time, not here.
func mapNetworkToObservedRequest(req *pendingRequest, pageURL string) ObservedRequest {
	obs := ObservedRequest{
		Method:  req.method,
		URL:     req.url,
		Headers: req.headers,
		Body:    []byte(req.body),
		Source:  "browser",
		PageURL: pageURL,
		Response: ObservedResponse{
			StatusCode:  req.statusCode,
			Headers:     req.respHeaders,
			ContentType: req.contentType,
			Body:        req.respBody,
		},
	}

	if obs.Method == "" {
		obs.Method = "GET"
	}

	if obs.URL != "" {
		if u, err := url.Parse(obs.URL); err == nil {
			obs.QueryParams = CapQueryValues(u.Query())
		}
	}

	return obs
}

func truncateBody(body []byte) []byte {
	if len(body) > MaxResponseBodySize {
		return body[:MaxResponseBodySize]
	}
	return body
}

// flattenNetworkHeaders lowercases header names.
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
