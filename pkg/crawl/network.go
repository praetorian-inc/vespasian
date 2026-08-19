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
	"time"

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

	// startedAt is when NetworkRequestWillBeSent fired for this request. Used by
	// networkState to age out a request that never completes so it stops
	// counting toward network-idle after the per-request timeout (LAB-4678 Phase 1).
	startedAt time.Time

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

	// order records request IDs in the sequence NetworkRequestWillBeSent first
	// observed them, so Results can emit a stable per-page order instead of
	// ranging the map (whose iteration order Go randomizes, making capture.json
	// differ byte-for-byte between runs on identical input). An ID is appended
	// only the first time it is seen: CDP reuses a request ID across a redirect
	// chain, and the handler overwrites the pending entry for it, so appending
	// unconditionally would emit that request more than once.
	order []proto.NetworkRequestID

	// lastActivity is the time of the most recent network event (request sent,
	// response received, loading finished/failed). Seeded at construction so it
	// is never zero, so a page that fires no requests still reads as idle after
	// the floor rather than waiting to the ceiling (LAB-4678 Phase 1).
	lastActivity time.Time
}

// newPageNetworkCapture creates a capture session and wires up CDP event
// listeners on the given page. The caller must call wait() (returned by
// setupListeners) after page navigation completes to ensure all events are
// processed.
func newPageNetworkCapture(page *rod.Page, pageURL string) (*pageNetworkCapture, func()) {
	c := &pageNetworkCapture{
		pending:      make(map[proto.NetworkRequestID]*pendingRequest),
		pageURL:      pageURL,
		page:         page,
		lastActivity: time.Now(),
	}
	wait := c.setupListeners(page)
	return c, wait
}

// recordSent registers a request that is about to be sent: it appends the ID to the
// order index ONCE and stores (or replaces) the pending entry. It sets startedAt and
// lastActivity itself, so callers pass only the request fields they read off the CDP
// event.
//
// The append is guarded because CDP REUSES a request ID across a redirect chain: the
// same ID fires RequestWillBeSent again for the new target, and the pending entry is
// overwritten so only the final hop survives. Appending unconditionally would put the
// ID in the order index once per hop and Results() would emit that request N times.
//
// This is a named method rather than an inline closure so a test can drive the real
// guard. The regression test used to build c.pending and c.order by hand and then
// re-implement the guard in its own body ("Mirrors the handler's guard"), which meant
// deleting the production guard left it green — it asserted against a copy of the code
// rather than the code (LAB-4678 review, TEST-008).
func (c *pageNetworkCapture) recordSent(id proto.NetworkRequestID, req *pendingRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if _, seen := c.pending[id]; !seen {
		c.order = append(c.order, id)
	}
	req.startedAt = now
	c.pending[id] = req
	c.lastActivity = now
}

// setupListeners registers CDP event handlers and returns a wait function.
// The wait function blocks until all registered events resolve. Callers
// should invoke it in a goroutine; it runs for the lifetime of the page.
func (c *pageNetworkCapture) setupListeners(page *rod.Page) func() {
	return page.EachEvent(
		func(e *proto.NetworkRequestWillBeSent) {
			c.recordSent(e.RequestID, &pendingRequest{
				method:  e.Request.Method,
				url:     e.Request.URL,
				headers: flattenNetworkHeaders(e.Request.Headers),
				body:    string(truncateBody([]byte(e.Request.PostData))),
			})
		},
		func(e *proto.NetworkResponseReceived) {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.lastActivity = time.Now()
			req, ok := c.pending[e.RequestID]
			if !ok {
				return
			}
			req.statusCode = e.Response.Status
			req.respHeaders = flattenNetworkHeaders(e.Response.Headers)
			req.contentType = e.Response.MIMEType
		},
		func(e *proto.NetworkLoadingFailed) {
			// A request that errored (blocked, aborted, DNS/TLS failure) will
			// never fire LoadingFinished. Mark it complete so it stops counting
			// as in-flight — otherwise network-idle is never reached and every
			// such page waits to the ceiling (LAB-4678 Phase 1).
			c.mu.Lock()
			defer c.mu.Unlock()
			c.lastActivity = time.Now()
			if req, ok := c.pending[e.RequestID]; ok {
				req.complete = true
			}
		},
		func(e *proto.NetworkLoadingFinished) {
			c.mu.Lock()
			c.lastActivity = time.Now()
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

// Results returns all captured network exchanges as ObservedRequest values, in
// the order the requests were first sent. Call this after navigation and DOM
// stability wait are complete.
//
// The order matters beyond aesthetics: capture.json is the pipeline's
// intermediate artifact and the README documents identical input as producing
// identical output, so a per-page order taken from Go's randomized map iteration
// made the artifact differ byte-for-byte between runs on the same target.
func (c *pageNetworkCapture) Results() []ObservedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	results := make([]ObservedRequest, 0, len(c.pending))
	for _, id := range c.order {
		req, ok := c.pending[id]
		if !ok {
			continue // defensive: order and pending are written together
		}
		results = append(results, mapNetworkToObservedRequest(req, c.pageURL))
	}
	return results
}

// networkState reports how many requests are still in flight and how long it has
// been since the last network activity, as of now. A request counts as in flight
// only while it has not completed AND its age is under perReqTimeout, so a single
// hung or never-finishing request stops blocking network-idle after perReqTimeout
// rather than pinning the crawl to the page ceiling. Drives the engine's
// completion-driven wait (LAB-4678 Phase 1).
func (c *pageNetworkCapture) networkState(perReqTimeout time.Duration, now time.Time) (inFlight int, sinceLastActivity time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, req := range c.pending {
		if !req.complete && now.Sub(req.startedAt) < perReqTimeout {
			inFlight++
		}
	}
	return inFlight, now.Sub(c.lastActivity)
}

// mapNetworkToObservedRequest converts a captured network exchange to an
// ObservedRequest and extracts query parameters. Body truncation is applied
// at collection time (NetworkRequestWillBeSent for request bodies,
// NetworkLoadingFinished for response bodies), not here.
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

	// Parse query parameters from URL.
	if obs.URL != "" {
		if u, err := url.Parse(obs.URL); err == nil {
			obs.QueryParams = CapQueryValues(u.Query())
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
