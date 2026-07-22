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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"
)

// checkpointVersion is the on-disk schema version. Load rejects a checkpoint
// written by a different version so a format change cannot be misread as valid
// resume state.
const checkpointVersion = 1

// DefaultCheckpointMaxAge bounds how old a checkpoint may be and still be reused.
// It is sized to Guard's crawl cadence (~5 days): coverage accumulates across a
// cycle, but a checkpoint older than this is discarded so the crawl does not
// resume from arbitrarily stale state (LAB-4678 Phase 4).
const DefaultCheckpointMaxAge = 5 * 24 * time.Hour

// Checkpoint is the cross-run resume state produced at the end of a (possibly
// truncated) crawl and consumed at the start of the next. It carries the pages
// still queued but not yet visited (Pending) so a resumed run continues the
// unvisited frontier instead of restarting, and the full set of URL keys already
// enqueued (Seen) so neither the resumed frontier nor newly-discovered links
// re-crawl covered pages. It is gated by ConfigFingerprint (a different crawl
// config invalidates it) and CreatedAtUnix (staleness).
//
// Storing and passing the checkpoint between runs is the caller's concern (for
// Guard, a platform piece coordinated separately); vespasian only produces,
// serializes, validates, and consumes it.
type Checkpoint struct {
	Version           int        `json:"version"`
	ConfigFingerprint string     `json:"config_fingerprint"`
	CreatedAtUnix     int64      `json:"created_at_unix"`
	Pending           []urlEntry `json:"pending"`
	Seen              []string   `json:"seen"`
}

// ComputeConfigFingerprint returns a stable hash of the crawl-defining inputs.
// A resumed run may only reuse a checkpoint whose fingerprint matches, so a
// change to the target, scope, or depth (which would change what the crawl
// covers) invalidates prior state rather than silently accumulating coverage
// across incompatible configs. MaxPages/MaxRequests are intentionally excluded:
// they bound a single run's budget, not what the crawl is allowed to cover, so a
// larger budget on resume should continue the same coverage, not invalidate it.
func ComputeConfigFingerprint(targetURL, scope string, depth int) string {
	// Length-prefix each field so ("a","b") and ("ab","") cannot collide, then
	// hash the assembled input in one shot.
	field := func(s string) string { return strconv.Itoa(len(s)) + ":" + s }
	input := field(targetURL) + field(scope) + field(strconv.Itoa(depth))
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// Save writes the checkpoint as JSON to w.
func (c *Checkpoint) Save(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("encode checkpoint: %w", err)
	}
	return nil
}

// LoadCheckpoint decodes a checkpoint from r and rejects an unknown schema
// version, so a format change fails closed rather than being misinterpreted.
func LoadCheckpoint(r io.Reader) (*Checkpoint, error) {
	var c Checkpoint
	if err := json.NewDecoder(r).Decode(&c); err != nil {
		return nil, fmt.Errorf("decode checkpoint: %w", err)
	}
	if c.Version != checkpointVersion {
		return nil, fmt.Errorf("checkpoint version %d unsupported (want %d)", c.Version, checkpointVersion)
	}
	return &c, nil
}

// Usable reports whether the checkpoint may be reused for a crawl with the given
// fingerprint as of now, and a human-readable reason when it may not. A
// mismatched config fingerprint or an age exceeding maxAge (measured from
// CreatedAtUnix) makes it unusable. A non-positive maxAge disables the staleness
// check (age is not considered).
func (c *Checkpoint) Usable(fingerprint string, now time.Time, maxAge time.Duration) (bool, string) {
	if c.Version != checkpointVersion {
		return false, fmt.Sprintf("version %d unsupported", c.Version)
	}
	if c.ConfigFingerprint != fingerprint {
		return false, "config fingerprint mismatch (target/scope/depth changed)"
	}
	if maxAge > 0 {
		age := now.Sub(time.Unix(c.CreatedAtUnix, 0))
		if age > maxAge {
			return false, fmt.Sprintf("checkpoint is stale (age %s > max %s)", age.Truncate(time.Second), maxAge)
		}
		if age < 0 {
			return false, "checkpoint timestamp is in the future"
		}
	}
	return true, ""
}

// Snapshot captures the frontier's current pending queue and full seen-set as a
// deterministic, resumable state. The seen keys are sorted so the serialized
// checkpoint is byte-stable for a given frontier state. Safe to call after the
// crawl's workers have stopped.
func (f *urlFrontier) Snapshot() (pending []urlEntry, seen []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pending = make([]urlEntry, len(f.queue))
	copy(pending, f.queue)
	seen = make([]string, 0, len(f.seen))
	for k := range f.seen {
		seen = append(seen, k)
	}
	sort.Strings(seen)
	return pending, seen
}

// Restore pre-loads resume state into the frontier before the crawl starts: the
// seen keys are marked so neither the restored queue nor newly-discovered links
// re-enqueue a covered page, and the pending entries are placed directly on the
// queue (they already passed scope/depth when first enqueued, and are already in
// seen, so they bypass Push's checks). Call on a fresh frontier before seeding.
func (f *urlFrontier) Restore(pending []urlEntry, seen []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range seen {
		f.seen[k] = true
	}
	f.queue = append(f.queue, pending...)
}
