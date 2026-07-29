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
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
)

func TestMapNetworkToObservedRequest_Normal(t *testing.T) {
	req := &pendingRequest{
		method:      "POST",
		url:         "https://example.com/api/users?page=1&limit=10",
		headers:     map[string]string{"content-type": "application/json"},
		body:        `{"name":"Alice"}`,
		statusCode:  201,
		respHeaders: map[string]string{"content-type": "application/json"},
		contentType: "application/json",
		respBody:    []byte(`{"id":1,"name":"Alice"}`),
		complete:    true,
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/app")

	if obs.Method != "POST" {
		t.Errorf("Method = %q, want %q", obs.Method, "POST")
	}
	if obs.URL != "https://example.com/api/users?page=1&limit=10" {
		t.Errorf("URL = %q, want original", obs.URL)
	}
	if obs.Source != "browser" {
		t.Errorf("Source = %q, want %q", obs.Source, "browser")
	}
	if obs.PageURL != "https://example.com/app" {
		t.Errorf("PageURL = %q, want %q", obs.PageURL, "https://example.com/app")
	}
	if len(obs.QueryParams["page"]) == 0 || obs.QueryParams["page"][0] != "1" {
		t.Errorf("QueryParams[page] = %v, want [1]", obs.QueryParams["page"])
	}
	if len(obs.QueryParams["limit"]) == 0 || obs.QueryParams["limit"][0] != "10" {
		t.Errorf("QueryParams[limit] = %v, want [10]", obs.QueryParams["limit"])
	}
	if string(obs.Body) != `{"name":"Alice"}` {
		t.Errorf("Body = %q, want request body", string(obs.Body))
	}
	if obs.Response.StatusCode != 201 {
		t.Errorf("Response.StatusCode = %d, want 201", obs.Response.StatusCode)
	}
	if obs.Response.ContentType != "application/json" {
		t.Errorf("Response.ContentType = %q, want %q", obs.Response.ContentType, "application/json")
	}
	if string(obs.Response.Body) != `{"id":1,"name":"Alice"}` {
		t.Errorf("Response.Body = %q, want response body", string(obs.Response.Body))
	}
}

func TestMapNetworkToObservedRequest_EmptyMethod(t *testing.T) {
	req := &pendingRequest{
		url: "https://example.com/page",
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/")
	if obs.Method != "GET" {
		t.Errorf("Method = %q, want %q (default)", obs.Method, "GET")
	}
}

func TestMapNetworkToObservedRequest_BodyPassthrough(t *testing.T) {
	// Bodies are truncated at collection time (in the CDP event handlers),
	// not in mapNetworkToObservedRequest. Verify the mapping passes
	// pre-truncated bodies through unchanged.
	truncatedBody := strings.Repeat("x", MaxResponseBodySize)

	req := &pendingRequest{
		method:   "GET",
		url:      "https://example.com/large",
		respBody: []byte(truncatedBody),
		body:     truncatedBody,
		complete: true,
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/")

	if len(obs.Response.Body) != MaxResponseBodySize {
		t.Errorf("Response.Body len = %d, want %d", len(obs.Response.Body), MaxResponseBodySize)
	}
	if len(obs.Body) != MaxResponseBodySize {
		t.Errorf("Body len = %d, want %d", len(obs.Body), MaxResponseBodySize)
	}
}

func TestTruncateBody_AtCollectionTime(t *testing.T) {
	// Verify truncateBody works correctly — this is called in the CDP
	// event handlers to bound memory at collection time.
	large := make([]byte, MaxResponseBodySize+500)
	for i := range large {
		large[i] = 'x'
	}
	got := truncateBody(large)
	if len(got) != MaxResponseBodySize {
		t.Errorf("truncateBody(large) len = %d, want %d", len(got), MaxResponseBodySize)
	}
}

func TestMapNetworkToObservedRequest_SmallBody(t *testing.T) {
	req := &pendingRequest{
		method:   "GET",
		url:      "https://example.com/small",
		respBody: []byte("small response"),
		complete: true,
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/")
	if string(obs.Response.Body) != "small response" {
		t.Errorf("Response.Body = %q, want %q", string(obs.Response.Body), "small response")
	}
}

func TestMapNetworkToObservedRequest_NoQueryParams(t *testing.T) {
	req := &pendingRequest{
		method: "GET",
		url:    "https://example.com/page",
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/")
	if len(obs.QueryParams) != 0 {
		t.Errorf("QueryParams = %v, want empty", obs.QueryParams)
	}
}

func TestMapNetworkToObservedRequest_NilHeaders(t *testing.T) {
	req := &pendingRequest{
		method: "GET",
		url:    "https://example.com/page",
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/")
	if obs.Headers != nil {
		t.Errorf("Headers = %v, want nil", obs.Headers)
	}
	if obs.Response.Headers != nil {
		t.Errorf("Response.Headers = %v, want nil", obs.Response.Headers)
	}
}

func TestTruncateBody(t *testing.T) {
	small := []byte("hello")
	if got := truncateBody(small); string(got) != "hello" {
		t.Errorf("truncateBody(small) = %q, want %q", string(got), "hello")
	}

	large := make([]byte, MaxResponseBodySize+500)
	for i := range large {
		large[i] = 'x'
	}
	if got := truncateBody(large); len(got) != MaxResponseBodySize {
		t.Errorf("truncateBody(large) len = %d, want %d", len(got), MaxResponseBodySize)
	}

	if got := truncateBody(nil); got != nil {
		t.Errorf("truncateBody(nil) = %v, want nil", got)
	}
}

func TestFlattenNetworkHeaders(t *testing.T) {
	headers := proto.NetworkHeaders{
		"Content-Type":    gson.New("application/json"),
		"X-Custom-Header": gson.New("value"),
	}

	flat := flattenNetworkHeaders(headers)
	if flat["content-type"] != "application/json" {
		t.Errorf("content-type = %q, want %q", flat["content-type"], "application/json")
	}
	if flat["x-custom-header"] != "value" {
		t.Errorf("x-custom-header = %q, want %q", flat["x-custom-header"], "value")
	}
}

func TestFlattenNetworkHeaders_Empty(t *testing.T) {
	flat := flattenNetworkHeaders(nil)
	if flat != nil {
		t.Errorf("flattenNetworkHeaders(nil) = %v, want nil", flat)
	}

	flat = flattenNetworkHeaders(proto.NetworkHeaders{})
	if flat != nil {
		t.Errorf("flattenNetworkHeaders({}) = %v, want nil", flat)
	}
}

// TestMapNetworkToObservedRequest_MultiValueQueryParam tests that multi-value query params are preserved.
func TestMapNetworkToObservedRequest_MultiValueQueryParam(t *testing.T) {
	req := &pendingRequest{
		method: "GET",
		url:    "https://example.com/api?tag=a&tag=b",
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/")

	if len(obs.QueryParams["tag"]) != 2 {
		t.Errorf("QueryParams[tag] length = %d, want 2", len(obs.QueryParams["tag"]))
	}
	if obs.QueryParams["tag"][0] != "a" || obs.QueryParams["tag"][1] != "b" {
		t.Errorf("QueryParams[tag] = %v, want [a b]", obs.QueryParams["tag"])
	}
}

// --- LAB-4678 Phase 1: completion-driven capture ---

func TestNetworkIdleReached(t *testing.T) {
	const floor = 500 * time.Millisecond
	const quiet = 500 * time.Millisecond

	cases := []struct {
		name            string
		inFlight        int
		sinceActivity   time.Duration
		elapsed         time.Duration
		deadlineReached bool
		want            bool
	}{
		// The page deadline outranks everything, including in-flight requests and
		// the floor: it is the whole page's budget, shared across the baseline
		// wait and every interaction wait, so it must be able to cut a wait short.
		{"deadline wins even with requests in flight", 3, 0, time.Second, true, true},
		{"deadline wins before the floor", 3, 0, 0, true, true},
		{"before floor never idle even if quiet", 0, time.Second, floor - time.Millisecond, false, false},
		{"past floor, idle and quiet -> stop", 0, quiet, floor, false, true},
		{"past floor but requests in flight -> wait", 2, quiet, floor + time.Second, false, false},
		{"past floor, idle but not quiet yet -> wait", 0, quiet - time.Millisecond, floor + time.Second, false, false},
		// A long-running page that has not hit its deadline keeps waiting, so the
		// stop decision never depends on elapsed time alone.
		{"no deadline, long elapsed, still busy -> wait", 1, 0, time.Hour, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := networkIdleReached(tc.inFlight, tc.sinceActivity, tc.elapsed, floor, quiet, tc.deadlineReached)
			if got != tc.want {
				t.Errorf("networkIdleReached(inFlight=%d, since=%v, elapsed=%v, deadlineReached=%v) = %v, want %v",
					tc.inFlight, tc.sinceActivity, tc.elapsed, tc.deadlineReached, got, tc.want)
			}
		})
	}
}

func TestNetworkState_InFlightCounting(t *testing.T) {
	now := time.Now()
	const perReq = 10 * time.Second
	c := &pageNetworkCapture{
		pending:      make(map[proto.NetworkRequestID]*pendingRequest),
		lastActivity: now.Add(-2 * time.Second),
	}
	// Completed request: never in flight.
	c.pending["done"] = &pendingRequest{startedAt: now.Add(-time.Second), complete: true}
	// Recent, incomplete: in flight.
	c.pending["live"] = &pendingRequest{startedAt: now.Add(-time.Second)}
	// Incomplete but older than perReq: aged out, not in flight.
	c.pending["hung"] = &pendingRequest{startedAt: now.Add(-perReq - time.Second)}

	inFlight, since := c.networkState(perReq, now)
	if inFlight != 1 {
		t.Errorf("inFlight = %d, want 1 (only the recent incomplete request counts)", inFlight)
	}
	if since != 2*time.Second {
		t.Errorf("sinceLastActivity = %v, want 2s", since)
	}
}

// TestPageNetworkCapture_ResultsOrderIsStable pins per-page capture order to the
// order requests were sent. Results used to range the pending map, so Go's
// randomized map iteration reordered every page's requests run-to-run and
// capture.json was not byte-stable for identical input.
func TestPageNetworkCapture_ResultsOrderIsStable(t *testing.T) {
	const n = 12 // enough that hitting the sent order by chance is not a concern
	c := &pageNetworkCapture{
		pending:      make(map[proto.NetworkRequestID]*pendingRequest),
		pageURL:      "https://ex.com/",
		lastActivity: time.Now(),
	}
	want := make([]string, 0, n)
	for i := range n {
		id := proto.NetworkRequestID(fmt.Sprintf("req-%02d", i))
		u := fmt.Sprintf("https://ex.com/api/%02d", i)
		c.pending[id] = &pendingRequest{method: "GET", url: u, complete: true}
		c.order = append(c.order, id)
		want = append(want, u)
	}

	for range 5 {
		got := make([]string, 0, n)
		for _, r := range c.Results() {
			got = append(got, r.URL)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("Results order = %v, want send order %v", got, want)
		}
	}
}

// TestPageNetworkCapture_RedirectReusedIDEmittedOnce guards the ordering index
// against double-counting: CDP reuses a request ID across a redirect chain and the
// request handler overwrites the pending entry, so appending to the order index
// unconditionally would emit that request more than once.
//
// It drives recordSent, the real production guard, rather than re-implementing it.
// The previous version built c.order by hand and copied the guard into its own body,
// so deleting the guard from network.go left this test green — it asserted against a
// copy of the code (LAB-4678 review, TEST-008). Verified by mutation: removing the
// `if _, seen := c.pending[id]; !seen` condition in recordSent fails this test.
func TestPageNetworkCapture_RedirectReusedIDEmittedOnce(t *testing.T) {
	c := &pageNetworkCapture{
		pending:      make(map[proto.NetworkRequestID]*pendingRequest),
		pageURL:      "https://ex.com/",
		lastActivity: time.Now(),
	}
	const id = proto.NetworkRequestID("shared")
	// First send, then the redirect hop reusing the same request ID. Both go through
	// the same path the CDP handler uses.
	c.recordSent(id, &pendingRequest{method: "GET", url: "https://ex.com/start", complete: true})
	c.recordSent(id, &pendingRequest{method: "GET", url: "https://ex.com/final", complete: true})

	got := c.Results()
	if len(got) != 1 {
		t.Fatalf("got %d results for one reused request ID, want 1: %+v", len(got), got)
	}
	if got[0].URL != "https://ex.com/final" {
		t.Errorf("URL = %q, want the post-redirect target", got[0].URL)
	}
}
