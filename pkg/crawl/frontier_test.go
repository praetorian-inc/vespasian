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
	"sync"
	"testing"
	"time"
)

func TestFrontier_BasicPushPop(t *testing.T) {
	f := newURLFrontier(10, nil)

	urls := []urlEntry{
		{URL: "https://example.com/a", Depth: 0},
		{URL: "https://example.com/b", Depth: 0},
		{URL: "https://example.com/c", Depth: 0},
	}
	added := f.Push(urls)
	if added != 3 {
		t.Fatalf("Push returned %d, want 3", added)
	}

	// FIFO order
	for _, want := range urls {
		got, ok := f.Pop()
		if !ok {
			t.Fatal("Pop returned false, expected URL")
		}
		if got.URL != want.URL {
			t.Errorf("Pop URL = %q, want %q", got.URL, want.URL)
		}
	}

	// Queue empty, no active workers → Pop returns false
	got, ok := f.Pop()
	if ok {
		t.Errorf("Pop returned true with URL %q, expected false (empty frontier)", got.URL)
	}
}

func TestFrontier_Dedup(t *testing.T) {
	f := newURLFrontier(10, nil)

	f.Push([]urlEntry{{URL: "https://example.com/page", Depth: 0}})
	f.Push([]urlEntry{{URL: "https://example.com/page", Depth: 0}})

	if f.Len() != 1 {
		t.Errorf("Len = %d, want 1 (dedup should prevent second push)", f.Len())
	}
	if f.Seen() != 1 {
		t.Errorf("Seen = %d, want 1", f.Seen())
	}
}

func TestFrontier_DedupFragment(t *testing.T) {
	f := newURLFrontier(10, nil)

	f.Push([]urlEntry{{URL: "https://example.com/page#top", Depth: 0}})
	added := f.Push([]urlEntry{{URL: "https://example.com/page#bottom", Depth: 0}})

	if added != 0 {
		t.Errorf("Push returned %d, want 0 (fragments should normalize to same URL)", added)
	}
	if f.Len() != 1 {
		t.Errorf("Len = %d, want 1", f.Len())
	}
}

func TestFrontier_ScopeFiltering(t *testing.T) {
	scopeFn := func(u string) bool {
		return u == "https://example.com/in-scope"
	}
	f := newURLFrontier(10, scopeFn)

	added := f.Push([]urlEntry{
		{URL: "https://example.com/in-scope", Depth: 0},
		{URL: "https://other.com/out-of-scope", Depth: 0},
	})

	if added != 1 {
		t.Errorf("Push returned %d, want 1 (one URL out of scope)", added)
	}
}

func TestFrontier_DepthLimit(t *testing.T) {
	f := newURLFrontier(2, nil)

	added := f.Push([]urlEntry{
		{URL: "https://example.com/depth0", Depth: 0},
		{URL: "https://example.com/depth1", Depth: 1},
		{URL: "https://example.com/depth2", Depth: 2},
		{URL: "https://example.com/depth3", Depth: 3}, // exceeds maxDepth
	})

	if added != 3 {
		t.Errorf("Push returned %d, want 3 (depth 3 should be rejected)", added)
	}
}

func TestFrontier_Close(t *testing.T) {
	f := newURLFrontier(10, nil)
	f.Close()

	// Push after close should reject
	added := f.Push([]urlEntry{{URL: "https://example.com/late", Depth: 0}})
	if added != 0 {
		t.Errorf("Push after Close returned %d, want 0", added)
	}

	// Pop on closed empty frontier returns false
	_, ok := f.Pop()
	if ok {
		t.Error("Pop on closed frontier returned true, want false")
	}
}

func TestFrontier_PopBlocksUntilPush(t *testing.T) {
	f := newURLFrontier(10, nil)

	// Simulate an active worker so Pop blocks instead of returning false immediately
	f.MarkActive()

	var got urlEntry
	var ok bool
	done := make(chan struct{})

	go func() {
		got, ok = f.Pop()
		close(done)
	}()

	// Give the goroutine time to block
	time.Sleep(50 * time.Millisecond)

	select {
	case <-done:
		t.Fatal("Pop returned before Push")
	default:
	}

	// Push a URL to unblock
	f.Push([]urlEntry{{URL: "https://example.com/unblock", Depth: 0}})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Pop did not return after Push")
	}

	if !ok {
		t.Error("Pop returned false after Push, want true")
	}
	if got.URL != "https://example.com/unblock" {
		t.Errorf("Pop URL = %q, want %q", got.URL, "https://example.com/unblock")
	}

	f.MarkIdle()
}

func TestFrontier_PopUnblocksOnMarkIdle(t *testing.T) {
	f := newURLFrontier(10, nil)

	// One active worker, empty queue → Pop should block
	f.MarkActive()

	done := make(chan bool, 1)
	go func() {
		_, ok := f.Pop()
		done <- ok
	}()

	time.Sleep(50 * time.Millisecond)

	// Mark idle with empty queue → frontier is exhausted → Pop returns false
	f.MarkIdle()

	select {
	case ok := <-done:
		if ok {
			t.Error("Pop returned true, want false (frontier exhausted)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Pop did not return after MarkIdle")
	}
}

func TestFrontier_ConcurrentAccess(t *testing.T) {
	f := newURLFrontier(100, nil)

	// Seed with initial URLs
	var initial []urlEntry
	for i := range 100 {
		initial = append(initial, urlEntry{
			URL:   "https://example.com/" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Depth: 0,
		})
	}
	f.Push(initial)

	// Concurrent consumers
	var wg sync.WaitGroup
	consumed := make(chan string, 200)

	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				entry, ok := f.Pop()
				if !ok {
					return
				}
				consumed <- entry.URL
			}
		}()
	}

	wg.Wait()
	close(consumed)

	count := 0
	for range consumed {
		count++
	}
	if count != 100 {
		t.Errorf("consumed %d URLs, want 100", count)
	}
}

func TestFrontier_ActiveWorkerPreventsEarlyDone(t *testing.T) {
	f := newURLFrontier(10, nil)

	// Push one URL, pop it, mark active
	f.Push([]urlEntry{{URL: "https://example.com/start", Depth: 0}})
	_, ok := f.Pop()
	if !ok {
		t.Fatal("Pop returned false, expected URL")
	}
	f.MarkActive()

	// Another goroutine tries to Pop — should block because a worker is active
	done := make(chan bool, 1)
	go func() {
		_, popOk := f.Pop()
		done <- popOk
	}()

	time.Sleep(50 * time.Millisecond)

	// Active worker discovers a new URL
	f.Push([]urlEntry{{URL: "https://example.com/discovered", Depth: 1}})
	f.MarkIdle()

	select {
	case popOk := <-done:
		if !popOk {
			t.Error("Pop returned false, want true (new URL was pushed)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Pop did not return after worker pushed URL and marked idle")
	}
}
