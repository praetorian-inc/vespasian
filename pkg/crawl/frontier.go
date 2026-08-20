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

import "sync"

// urlEntry represents a URL in the frontier with its crawl depth.
//
// It is an alias for the exported [PendingURL] rather than its own type: the same
// value is both the frontier's internal queue element and the element type of
// [Checkpoint.Pending], which an external host (Guard) must be able to construct
// and inspect. One type keeps the frontier's short internal name at the call sites
// that read best with it while leaving the checkpoint's wire type exported.
type urlEntry = PendingURL

// urlFrontier is a thread-safe queue of URLs to visit, with deduplication,
// scope filtering, and depth tracking. Workers call Pop to get the next URL and
// Push to enqueue discovered links. The frontier detects completion when the
// queue is empty and no workers are actively processing a page.
// By default the queue is FIFO (BFS). Call SetDFS(true) to switch to LIFO (DFS).
type urlFrontier struct {
	mu       sync.Mutex
	cond     *sync.Cond
	queue    []urlEntry
	seen     map[string]bool
	maxDepth int
	scopeFn  func(string) bool
	active   int  // workers currently navigating a page
	closed   bool // set by Close(); prevents new pushes
	dfs      bool // when true, Pop uses LIFO order (depth-first)

	// failed holds pages that were VISITED AND FAILED transiently, keyed by dedup
	// key. They stay in `seen` so this run does not retry them (a persistently
	// broken page linked from many pages would otherwise be re-attempted once per
	// referrer and spend the page budget on it), but Snapshot excludes them from
	// the checkpoint's seen-set AND re-adds them to its pending queue so a later
	// resumed run tries them again. See [urlFrontier.MarkFailed].
	//
	// The full entry is stored, not just a bool, because Snapshot needs the
	// entry's Depth to put it back on the pending queue. Omitting it from seen is
	// not sufficient on its own: a popped-and-failed page is in neither the queue
	// nor seen, so it would be carried in neither half of the checkpoint and
	// survive only if some other pending page happens to re-link it.
	failed map[string]urlEntry

	// variants counts how many distinct query variants of each path have been
	// admitted, so a path may be visited more than once when its query string
	// changes. See [maxQueryVariantsPerPath].
	variants map[string]int
}

// maxQueryVariantsPerPath bounds how many distinct query strings one path may be
// crawled with.
//
// Collapsing every query variant of a path to a single visit assumes the query
// only selects WHICH row a page shows, not WHAT the page does — true for
// /product?id=1 versus /product?id=2, and false for the two shapes that matter:
// pagination (?page=2 commonly fires a different XHR than page 1) and
// query-switched views (?tab=billing, ?view=admin), where one query value can be
// the only route into a whole section of the app. Normalizing the PATH does not
// normalize the RESULTS.
//
// A cap keeps most of what collapsing bought — a catalog with 5,000 ?id= values
// still costs a handful of visits instead of 5,000 — while leaving room for the
// handful of variants that carry distinct surface. It is not a measured
// distribution over real targets; it is a deliberate ceiling chosen so the
// pathological case stays bounded and the common case (a page reached with two or
// three different query strings) is no longer silently dropped. Re-tune it
// against real Guard runs rather than treating it as settled.
const maxQueryVariantsPerPath = 4

// newURLFrontier creates a frontier with the given max depth and scope filter.
// The scopeFn is called for every URL before enqueuing; returning false rejects
// the URL. A nil scopeFn accepts all URLs.
func newURLFrontier(maxDepth int, scopeFn func(string) bool) *urlFrontier {
	f := &urlFrontier{
		queue:    make([]urlEntry, 0, 64),
		seen:     make(map[string]bool),
		failed:   make(map[string]urlEntry),
		variants: make(map[string]int),
		maxDepth: maxDepth,
		scopeFn:  scopeFn,
	}
	f.cond = sync.NewCond(&f.mu)
	return f
}

// Push adds URLs to the frontier if they pass scope, depth, and dedup checks.
// Returns the number of URLs actually enqueued.
func (f *urlFrontier) Push(entries []urlEntry) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return 0
	}

	added := 0
	for _, e := range entries {
		// Depth check: entries at depth > maxDepth are links we would visit
		// at maxDepth+1, which exceeds the configured limit.
		if f.maxDepth >= 0 && e.Depth > f.maxDepth {
			continue
		}

		// Dedup on the FULL canonical URL, so two links differing only in query
		// string are distinct entries, and bound how many variants of one path
		// may be admitted (LAB-4678 Phase 1, revised).
		//
		// Deduping on the query-stripped key alone collapsed every variant to one
		// visit. That saved budget on /product?id=N, and silently lost ?page=2 and
		// ?tab=billing, which are separate pages wearing the same path.
		normalized := seenKey(e.URL)
		if normalized == "" {
			continue
		}
		pathKey := frontierKey(e.URL)
		if pathKey == "" {
			continue
		}

		if f.seen[normalized] {
			continue
		}

		// A path gets one free visit plus maxQueryVariantsPerPath-1 further query
		// variants. The first visit of a path always passes, so a target with no
		// query strings behaves exactly as before.
		if f.variants[pathKey] >= maxQueryVariantsPerPath {
			continue
		}

		if f.scopeFn != nil && !f.scopeFn(e.URL) {
			continue
		}

		f.seen[normalized] = true
		f.variants[pathKey]++
		f.queue = append(f.queue, e)
		added++
	}

	if added > 0 {
		f.cond.Broadcast()
	}
	return added
}

// Requeue returns a popped-but-unvisited entry to the queue so it is not lost.
// Push cannot be used for this: the entry's key is already in seen, so Push
// would reject it. The key deliberately STAYS in seen, so a link rediscovered
// later still dedups against it — only this specific abandoned entry is
// restored.
//
// Callers must still call MarkIdle after Requeue, exactly as after any Pop. Use
// this whenever a worker gives up an entry without covering it (a crawl budget
// was reached, or the context was canceled): the page is genuinely unvisited, so
// it belongs in the pending queue for cross-run resume ([urlFrontier.Snapshot])
// rather than silently dropped (LAB-4678 Phase 4). Dropping it made a
// budget-truncated crawl lose its entire pending queue at default concurrency,
// which is the exact case resume exists to carry forward.
func (f *urlFrontier) Requeue(e urlEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.queue = append(f.queue, e)
	f.cond.Broadcast()
}

// MarkFailed records that the page at e.URL was attempted and failed for a
// reason that is plausibly transient (navigation error, DNS blip, connection
// reset, rate-limiter timeout) while the crawl itself was still healthy.
//
// The key deliberately STAYS in seen, so this run will not retry the page: a
// broken page linked from many others would otherwise be re-attempted once per
// referrer, and every attempt reserves a slot from the page budget. What changes
// is the CHECKPOINT: [urlFrontier.Snapshot] omits failed keys from the persisted
// seen-set AND returns the entry on the pending queue, so the next resumed run
// treats the page as never covered and tries it again. Without this, seen is
// cumulative across every resume cycle, so a single one-off 503 blacklisted the
// page permanently for the life of the checkpoint.
//
// The whole entry is taken rather than just the URL because Snapshot needs its
// Depth to requeue it. Omitting the key from seen without requeuing it loses the
// page entirely: it was popped, so it is not in the queue either, and it would
// then be retried only if another pending page happens to link it again.
//
// Callers must still call MarkIdle afterwards, exactly as after any Pop.
func (f *urlFrontier) MarkFailed(e urlEntry) {
	// Keyed on the same identity as `seen` (seenKey, the full canonical URL), so a
	// failed ?page=2 is excluded from the persisted seen-set without also un-seeing
	// ?page=1, which is now a separate entry.
	key := seenKey(e.URL)
	if key == "" {
		return
	}
	f.mu.Lock()
	f.failed[key] = e
	f.mu.Unlock()
}

// SetDFS switches the frontier to depth-first (LIFO) pop order when v is true,
// or back to breadth-first (FIFO) when v is false. The mutation is
// mutex-protected and is therefore safe from data races. However, SetDFS is
// intended to be called before the first Push: calling it after workers have
// started produces a non-deterministic mid-crawl traversal-order change (a
// logical race), not a data race.
func (f *urlFrontier) SetDFS(v bool) {
	f.mu.Lock()
	f.dfs = v
	f.mu.Unlock()
}

// Pop returns the next URL to visit, atomically marking the entry as active.
// It blocks until a URL is available or the frontier is done (empty queue, no
// active workers, or closed). Returns (entry, true) on success or
// (urlEntry{}, false) when the frontier is exhausted.
// When SetDFS(true) has been called, Pop returns the last-pushed entry (LIFO).
//
// Active tracking is incremented inside Pop's critical section before the
// mutex is released, making dequeue+activate atomic. This closes the TOCTOU
// window where a concurrent Pop could observe an empty queue with active==0
// while another worker holds an entry but has not yet called MarkActive.
// Callers MUST call MarkIdle() exactly once when done processing the entry.
func (f *urlFrontier) Pop() (urlEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for {
		if len(f.queue) > 0 {
			var entry urlEntry
			if f.dfs {
				// LIFO: take the last element. Clear the popped slot before
				// reslicing so the backing array does not retain the entry
				// (GC concern on large DFS crawls — mirrors the FIFO path).
				last := len(f.queue) - 1
				entry = f.queue[last]
				f.queue[last] = urlEntry{}
				f.queue = f.queue[:last]
			} else {
				// FIFO: take the first element. Zero the dequeued slot before
				// advancing so the backing array does not retain it between
				// compactions (same GC concern handled in the DFS branch).
				entry = f.queue[0]
				f.queue[0] = urlEntry{}
				f.queue = f.queue[1:]
				// Compact the backing array when it's 4x larger than needed.
				// Without this, consumed slots hold stale entries that can't
				// be GC'd — a memory concern on large crawls.
				if cap(f.queue) > 4*len(f.queue) && len(f.queue) > 0 {
					compact := make([]urlEntry, len(f.queue))
					copy(compact, f.queue)
					f.queue = compact
				}
			}
			// Atomically mark this worker as active so concurrent Pop calls
			// block instead of returning false when the queue drains.
			f.active++
			return entry, true
		}

		// Queue is empty. If no workers are active (and thus no new URLs can
		// arrive), or the frontier is closed, we're done.
		if f.active == 0 || f.closed {
			return urlEntry{}, false
		}

		// Wait for Push or MarkIdle to signal.
		f.cond.Wait()
	}
}

// MarkIdle decrements the active-worker counter. Call this when a worker
// finishes processing a URL (after pushing discovered links). If the queue
// is empty and no workers are active, waiting Pop calls are unblocked.
func (f *urlFrontier) MarkIdle() {
	f.mu.Lock()
	f.active--
	if f.active == 0 && len(f.queue) == 0 {
		f.cond.Broadcast()
	}
	f.mu.Unlock()
}

// Close signals that no more URLs will be added externally. Any blocked Pop
// calls will return false once the queue drains.
func (f *urlFrontier) Close() {
	f.mu.Lock()
	f.closed = true
	f.cond.Broadcast()
	f.mu.Unlock()
}

// Len returns the number of URLs currently in the queue (not including
// URLs being actively processed by workers).
func (f *urlFrontier) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queue)
}

// Seen returns the total number of unique URLs that have been enqueued
// (including those already processed).
func (f *urlFrontier) Seen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}
