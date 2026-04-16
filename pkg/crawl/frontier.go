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
type urlEntry struct {
	URL   string
	Depth int
}

// urlFrontier is a thread-safe FIFO queue of URLs to visit, with deduplication,
// scope filtering, and depth tracking. Workers call Pop to get the next URL and
// Push to enqueue discovered links. The frontier detects completion when the
// queue is empty and no workers are actively processing a page.
type urlFrontier struct {
	mu       sync.Mutex
	cond     *sync.Cond
	queue    []urlEntry
	seen     map[string]bool
	maxDepth int
	scopeFn  func(string) bool
	active   int  // workers currently navigating a page
	closed   bool // set by Close(); prevents new pushes
}

// newURLFrontier creates a frontier with the given max depth and scope filter.
// The scopeFn is called for every URL before enqueuing; returning false rejects
// the URL. A nil scopeFn accepts all URLs.
func newURLFrontier(maxDepth int, scopeFn func(string) bool) *urlFrontier {
	f := &urlFrontier{
		queue:    make([]urlEntry, 0, 64),
		seen:     make(map[string]bool),
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

		normalized := normalizeURL(e.URL)
		if normalized == "" {
			continue
		}

		if f.seen[normalized] {
			continue
		}

		if f.scopeFn != nil && !f.scopeFn(e.URL) {
			continue
		}

		f.seen[normalized] = true
		f.queue = append(f.queue, e)
		added++
	}

	if added > 0 {
		f.cond.Broadcast()
	}
	return added
}

// Pop returns the next URL to visit. It blocks until a URL is available or
// the frontier is done (empty queue, no active workers, or closed). Returns
// (entry, true) on success or (urlEntry{}, false) when the frontier is exhausted.
func (f *urlFrontier) Pop() (urlEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for {
		if len(f.queue) > 0 {
			entry := f.queue[0]
			f.queue = f.queue[1:]
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

// MarkActive increments the active-worker counter. Call this when a worker
// receives a URL from Pop and begins processing it.
func (f *urlFrontier) MarkActive() {
	f.mu.Lock()
	f.active++
	f.mu.Unlock()
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
