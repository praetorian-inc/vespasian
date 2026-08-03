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

// urlFrontier is a thread-safe queue with dedup, scope filtering and depth
// tracking. Complete when the queue is empty and no worker is active. FIFO (BFS)
// unless SetDFS(true).
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
}

// newURLFrontier calls scopeFn before enqueuing each URL; nil accepts everything.
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

// Push returns the number enqueued after scope, depth and dedup checks.
func (f *urlFrontier) Push(entries []urlEntry) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return 0
	}

	added := 0
	for _, e := range entries {

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

// SetDFS switches pop order. Mutex-protected, so no data race, but call it before
// the first Push: mid-crawl it changes traversal order non-deterministically.
func (f *urlFrontier) SetDFS(v bool) {
	f.mu.Lock()
	f.dfs = v
	f.mu.Unlock()
}

// Pop blocks until an entry is available or the frontier is exhausted.
//
// The active counter is incremented inside Pop's critical section, making
// dequeue+activate atomic. That closes the TOCTOU window where a concurrent Pop
// sees an empty queue with active==0 while another worker holds an entry but has
// not yet marked itself active. Callers MUST call MarkIdle() exactly once.
func (f *urlFrontier) Pop() (urlEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for {
		if len(f.queue) > 0 {
			var entry urlEntry
			if f.dfs {
				// Clear the slot before reslicing or the backing array retains it.
				last := len(f.queue) - 1
				entry = f.queue[last]
				f.queue[last] = urlEntry{}
				f.queue = f.queue[:last]
			} else {
				// Zero before advancing, same reason.
				entry = f.queue[0]
				f.queue[0] = urlEntry{}
				f.queue = f.queue[1:]
				// Compact at 4x: consumed slots otherwise pin stale entries.
				if cap(f.queue) > 4*len(f.queue) && len(f.queue) > 0 {
					compact := make([]urlEntry, len(f.queue))
					copy(compact, f.queue)
					f.queue = compact
				}
			}
			// Marked active here so a concurrent Pop blocks rather than returning
			// false as the queue drains.
			f.active++
			return entry, true
		}

		// Empty and nobody active means no new URLs can arrive.
		if f.active == 0 || f.closed {
			return urlEntry{}, false
		}

		f.cond.Wait()
	}
}

// MarkIdle decrements the active counter, after pushing discovered links.
func (f *urlFrontier) MarkIdle() {
	f.mu.Lock()
	f.active--
	if f.active == 0 && len(f.queue) == 0 {
		f.cond.Broadcast()
	}
	f.mu.Unlock()
}

// Close makes blocked Pop calls return false once the queue drains.
func (f *urlFrontier) Close() {
	f.mu.Lock()
	f.closed = true
	f.cond.Broadcast()
	f.mu.Unlock()
}

// Len excludes URLs being actively processed.
func (f *urlFrontier) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queue)
}

// Seen counts every unique URL ever enqueued.
func (f *urlFrontier) Seen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}
