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

	// FIFO order. Each Pop atomically marks this worker active; MarkIdle signals
	// that the worker finished processing (no new links discovered).
	for _, want := range urls {
		got, ok := f.Pop()
		if !ok {
			t.Fatal("Pop returned false, expected URL")
		}
		if got.URL != want.URL {
			t.Errorf("Pop URL = %q, want %q", got.URL, want.URL)
		}
		f.MarkIdle() // worker done; active counter decremented
	}

	// Queue empty, no active workers → Pop returns false immediately.
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

	// Seed one URL so worker 1 can Pop it and keep the frontier alive (active>0).
	// Worker 2 then blocks because the queue is empty but active>0.
	f.Push([]urlEntry{{URL: "https://example.com/seed", Depth: 0}})

	// Worker 1: Pop the seed entry. Pop atomically sets active=1.
	worker1Ready := make(chan struct{})
	worker1Done := make(chan struct{})
	go func() {
		e, ok := f.Pop()
		if !ok || e.URL == "" {
			return // test will fail via worker2 check
		}
		close(worker1Ready)
		// Hold the entry (keep active=1) until worker 2 has pushed something.
		<-worker1Done
		f.MarkIdle()
	}()

	// Wait for worker 1 to have popped (active=1).
	select {
	case <-worker1Ready:
	case <-time.After(2 * time.Second):
		t.Fatal("worker 1 did not pop seed in time")
	}

	// Worker 2: Pop blocks (queue empty, active=1).
	var got urlEntry
	var ok bool
	done := make(chan struct{})
	go func() {
		got, ok = f.Pop()
		close(done)
	}()

	// Give worker 2 time to block.
	time.Sleep(50 * time.Millisecond)

	select {
	case <-done:
		t.Fatal("Pop returned before Push")
	default:
	}

	// Push a URL to unblock worker 2.
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

	// Release worker 1 to call MarkIdle; worker 2's MarkIdle.
	close(worker1Done)
	f.MarkIdle()
}

func TestFrontier_PopUnblocksOnMarkIdle(t *testing.T) {
	f := newURLFrontier(10, nil)

	// Seed one URL. Worker 1 pops it (active=1), keeping the frontier alive.
	// Worker 2 blocks on Pop (queue empty, active=1). When worker 1 calls
	// MarkIdle (active→0, queue still empty), worker 2 unblocks with false.
	f.Push([]urlEntry{{URL: "https://example.com/seed", Depth: 0}})

	// Worker 1 holds its entry until we signal it to call MarkIdle.
	release := make(chan struct{})
	w1ready := make(chan struct{})
	go func() {
		e, _ := f.Pop() // active becomes 1
		_ = e
		close(w1ready)
		<-release
		f.MarkIdle() // active goes 0, queue empty → unblocks worker 2
	}()

	// Wait for worker 1 to have popped.
	select {
	case <-w1ready:
	case <-time.After(2 * time.Second):
		t.Fatal("worker 1 did not pop in time")
	}

	// Worker 2: Pop should block (queue empty, active=1).
	done := make(chan bool, 1)
	go func() {
		_, ok := f.Pop()
		done <- ok
	}()

	time.Sleep(50 * time.Millisecond)

	// Release worker 1 to call MarkIdle → frontier exhausted → Pop returns false.
	close(release)

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

	// Concurrent consumers. Each Pop atomically marks the worker active; MarkIdle
	// must be called after processing so the frontier knows when work is done.
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
				f.MarkIdle() // signal that this worker finished processing
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

func TestFrontier_DFSPopOrder(t *testing.T) {
	f := newURLFrontier(10, nil)
	f.SetDFS(true)
	f.Push([]urlEntry{{URL: "https://e.com/a", Depth: 0}})
	f.Push([]urlEntry{{URL: "https://e.com/b", Depth: 0}})
	// With the atomic-Pop fix, Pop increments active internally; no separate
	// MarkActive call is needed to keep the frontier "live" during the second Pop.
	e1, ok1 := f.Pop()
	if !ok1 {
		t.Fatal("DFS pop1 returned false, want true")
	}
	if e1.URL != "https://e.com/b" {
		t.Errorf("DFS pop1 = %s, want .../b", e1.URL)
	}
	e2, ok2 := f.Pop()
	if !ok2 {
		t.Fatal("DFS pop2 returned false, want true")
	}
	if e2.URL != "https://e.com/a" {
		t.Errorf("DFS pop2 = %s, want .../a", e2.URL)
	}
	f.MarkIdle()
	f.MarkIdle()
}

// TestFrontier_SingleSeedBlocksOtherWorkers verifies the atomicity invariant:
// after one Pop with a single seed, other concurrent Pop calls must BLOCK
// (not return false) because the popped worker is still active. This is the
// regression guard for the empty-queue+active==0 collapse described in QUAL-003.
func TestFrontier_SingleSeedBlocksOtherWorkers(t *testing.T) {
	f := newURLFrontier(10, nil)
	f.Push([]urlEntry{{URL: "https://example.com/seed", Depth: 0}})

	// Worker 1 pops the only entry. With the atomic fix, Pop increments active
	// before returning, so other workers see active>0 and block.
	entry, ok := f.Pop()
	if !ok {
		t.Fatal("first Pop returned false, expected seed entry")
	}
	if entry.URL != "https://example.com/seed" {
		t.Errorf("first Pop URL = %q, want seed", entry.URL)
	}

	// Worker 2 tries to Pop concurrently. The queue is empty but active>0 (worker 1
	// is still processing). Worker 2 must block, not return false.
	done := make(chan bool, 1)
	go func() {
		_, popOk := f.Pop()
		done <- popOk
	}()

	// Confirm worker 2 is blocking (not immediately returning false).
	select {
	case result := <-done:
		t.Fatalf("second Pop returned immediately with ok=%v, want it to block (queue empty but worker active)", result)
	case <-time.After(100 * time.Millisecond):
		// Expected: worker 2 is blocked.
	}

	// Worker 1 pushes a child URL, then marks idle.
	f.Push([]urlEntry{{URL: "https://example.com/child", Depth: 1}})
	f.MarkIdle()

	// Worker 2 should now unblock with the child URL.
	select {
	case popOk := <-done:
		if !popOk {
			t.Error("second Pop returned false after child pushed, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Pop did not unblock after child URL pushed + MarkIdle")
	}
	// Worker 2 consumed the child; frontier now idle.
	f.MarkIdle()
}

func TestFrontier_ActiveWorkerPreventsEarlyDone(t *testing.T) {
	f := newURLFrontier(10, nil)

	// Push one URL; Pop atomically marks this worker active — no separate MarkActive needed.
	f.Push([]urlEntry{{URL: "https://example.com/start", Depth: 0}})
	_, ok := f.Pop()
	if !ok {
		t.Fatal("Pop returned false, expected URL")
	}
	// active==1 here because Pop incremented it atomically.

	// Another goroutine tries to Pop — should block because a worker is active
	done := make(chan bool, 1)
	go func() {
		_, popOk := f.Pop()
		done <- popOk
	}()

	time.Sleep(50 * time.Millisecond)

	// Active worker discovers a new URL
	f.Push([]urlEntry{{URL: "https://example.com/discovered", Depth: 1}})
	f.MarkIdle() // worker 1 done (active goes 1→0, but Push unblocked worker 2 already)

	select {
	case popOk := <-done:
		if !popOk {
			t.Error("Pop returned false, want true (new URL was pushed)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Pop did not return after worker pushed URL and marked idle")
	}
	// Worker 2 consumed the discovered URL (active incremented by its Pop).
	f.MarkIdle()
}

// TestFrontier_DedupQueryVariants verifies URLs differing only in query params
// collapse to one frontier entry, so the crawler visits the page template once
// rather than spending the page budget on near-duplicate variants (LAB-4678
// Phase 1). Distinct paths remain distinct.
func TestFrontier_DedupQueryVariants(t *testing.T) {
	f := newURLFrontier(10, nil)

	f.Push([]urlEntry{{URL: "https://example.com/product?id=1", Depth: 0}})
	added := f.Push([]urlEntry{{URL: "https://example.com/product?id=2&ref=x", Depth: 0}})
	if added != 0 {
		t.Errorf("Push returned %d, want 0 (query-only difference must dedup)", added)
	}
	if f.Len() != 1 {
		t.Errorf("Len = %d, want 1", f.Len())
	}

	// A genuinely different path is still enqueued.
	added = f.Push([]urlEntry{{URL: "https://example.com/category?id=1", Depth: 0}})
	if added != 1 {
		t.Errorf("Push returned %d, want 1 (distinct path)", added)
	}

	// The first-seen variant (with its query) is what gets queued/fetched.
	entry, ok := f.Pop()
	if !ok || entry.URL != "https://example.com/product?id=1" {
		t.Errorf("Pop = %q (ok=%v), want the first-seen variant with its query", entry.URL, ok)
	}
}
