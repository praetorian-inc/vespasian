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
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestComputeConfigFingerprint(t *testing.T) {
	base := ComputeConfigFingerprint("https://ex.com", "same-origin", 3, true, false)
	if base == "" {
		t.Fatal("empty fingerprint")
	}
	if base != ComputeConfigFingerprint("https://ex.com", "same-origin", 3, true, false) {
		t.Error("fingerprint not stable for identical inputs")
	}
	// Each defining field changes the fingerprint, including the backend: the
	// two backends discover different link sets, so a headless checkpoint must
	// not be reusable by the net/http backend.
	for _, fp := range []string{
		ComputeConfigFingerprint("https://other.com", "same-origin", 3, true, false),
		ComputeConfigFingerprint("https://ex.com", "same-domain", 3, true, false),
		ComputeConfigFingerprint("https://ex.com", "same-origin", 5, true, false),
		ComputeConfigFingerprint("https://ex.com", "same-origin", 3, false, false),
		// allowPrivate: without this case a regression dropping it from the
		// fingerprint would let a --dangerous-allow-private checkpoint be resumed
		// by a run without the flag, and this test would stay green.
		ComputeConfigFingerprint("https://ex.com", "same-origin", 3, true, true),
	} {
		if fp == base {
			t.Error("fingerprint did not change when a defining field changed")
		}
	}
	// Length-prefixing prevents field-boundary collisions.
	if ComputeConfigFingerprint("ab", "", 0, true, false) == ComputeConfigFingerprint("a", "b", 0, true, false) {
		t.Error("field-boundary collision")
	}
}

// TestResumeOptions_MaxAgeDefault verifies an unset MaxAge falls back to the
// default rather than disabling the staleness check — an unset field must not
// silently remove protection.
func TestResumeOptions_MaxAgeDefault(t *testing.T) {
	for _, v := range []time.Duration{0, -time.Hour} {
		if got := (resumeOptions{MaxAge: v}).maxAgeOrDefault(); got != DefaultCheckpointMaxAge {
			t.Errorf("maxAgeOrDefault(%v) = %v, want %v", v, got, DefaultCheckpointMaxAge)
		}
	}
	if got := (resumeOptions{MaxAge: time.Minute}).maxAgeOrDefault(); got != time.Minute {
		t.Errorf("explicit MaxAge not honored: %v", got)
	}
}

// TestResumeFrontier verifies the restore gate: a usable checkpoint is applied,
// and an absent or unusable one degrades to a fresh crawl rather than failing.
func TestResumeFrontier(t *testing.T) {
	now := time.Unix(100000, 0)
	const fp = "fp"
	mkCP := func(fingerprint string, created int64) *Checkpoint {
		return &Checkpoint{
			Version:           checkpointVersion,
			ConfigFingerprint: fingerprint,
			CreatedAtUnix:     created,
			Pending:           []urlEntry{{URL: "https://ex.com/a", Depth: 1}},
			Seen:              []string{"https://ex.com/", "https://ex.com/a"},
		}
	}

	t.Run("usable checkpoint restores", func(t *testing.T) {
		f := newURLFrontier(10, nil)
		var out bytes.Buffer
		if !resumeFrontier(f, resumeOptions{From: mkCP(fp, now.Unix()), Fingerprint: fp}, now, &out) {
			t.Fatal("usable checkpoint was not applied")
		}
		if f.Len() != 1 {
			t.Errorf("restored queue len = %d, want 1", f.Len())
		}
		if !strings.Contains(out.String(), "resume: restored") {
			t.Errorf("restore not announced on stderr: %q", out.String())
		}
	})

	t.Run("nil checkpoint is a fresh crawl", func(t *testing.T) {
		f := newURLFrontier(10, nil)
		var out bytes.Buffer
		if resumeFrontier(f, resumeOptions{Fingerprint: fp}, now, &out) {
			t.Error("nil checkpoint reported as resumed")
		}
		if out.Len() != 0 {
			t.Errorf("nil checkpoint should be silent, got %q", out.String())
		}
	})

	// A mismatched or stale checkpoint must warn and continue, never abort: a
	// config change should cost a full re-crawl, not a failed run.
	for _, tc := range []struct {
		name string
		cp   *Checkpoint
	}{
		{"fingerprint mismatch", mkCP("other", now.Unix())},
		{"stale", mkCP(fp, now.Add(-DefaultCheckpointMaxAge-time.Hour).Unix())},
	} {
		t.Run(tc.name+" warns and starts fresh", func(t *testing.T) {
			f := newURLFrontier(10, nil)
			var out bytes.Buffer
			if resumeFrontier(f, resumeOptions{From: tc.cp, Fingerprint: fp}, now, &out) {
				t.Error("unusable checkpoint reported as resumed")
			}
			if f.Len() != 0 {
				t.Errorf("unusable checkpoint still restored %d entries", f.Len())
			}
			if !strings.Contains(out.String(), "ignoring checkpoint") {
				t.Errorf("no warning emitted: %q", out.String())
			}
		})
	}
}

// TestCaptureCheckpoint verifies the produced checkpoint is stamped with the
// current config identity and carries the frontier's unvisited state, and that
// it is a no-op without a callback.
func TestCaptureCheckpoint(t *testing.T) {
	now := time.Unix(100000, 0)
	f := newURLFrontier(10, nil)
	f.Push([]urlEntry{{URL: "https://ex.com/a", Depth: 1}})

	var got *Checkpoint
	captureCheckpoint(f, resumeOptions{Fingerprint: "fp", On: func(c *Checkpoint) { got = c }}, now)
	if got == nil {
		t.Fatal("callback not invoked")
	}
	if got.Version != checkpointVersion || got.ConfigFingerprint != "fp" || got.CreatedAtUnix != now.Unix() {
		t.Errorf("checkpoint not stamped correctly: %+v", got)
	}
	if len(got.Pending) != 1 || got.Pending[0].URL != "https://ex.com/a" {
		t.Errorf("pending not captured: %+v", got.Pending)
	}
	if len(got.Seen) != 1 {
		t.Errorf("seen = %v, want 1 entry", got.Seen)
	}

	// No callback: must not panic and must not snapshot.
	captureCheckpoint(f, resumeOptions{Fingerprint: "fp"}, now)
}

func TestCheckpoint_SaveLoadRoundTrip(t *testing.T) {
	cp := &Checkpoint{
		Version:           checkpointVersion,
		ConfigFingerprint: "fp",
		CreatedAtUnix:     1000,
		Pending:           []urlEntry{{URL: "https://ex.com/a", Depth: 1}},
		Seen:              []string{"https://ex.com/", "https://ex.com/a"},
	}
	var buf bytes.Buffer
	if err := cp.Save(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCheckpoint(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigFingerprint != "fp" || len(got.Pending) != 1 || got.Pending[0].URL != "https://ex.com/a" || len(got.Seen) != 2 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestLoadCheckpoint_RejectsVersion(t *testing.T) {
	cp := &Checkpoint{Version: 999, ConfigFingerprint: "fp"}
	var buf bytes.Buffer
	if err := cp.Save(&buf); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCheckpoint(&buf); err == nil {
		t.Error("expected version-rejection error, got nil")
	}
}

func TestCheckpoint_Usable(t *testing.T) {
	now := time.Unix(100000, 0)
	mk := func(fp string, created int64) *Checkpoint {
		return &Checkpoint{Version: checkpointVersion, ConfigFingerprint: fp, CreatedAtUnix: created}
	}

	if ok, _ := mk("fp", now.Add(-time.Hour).Unix()).Usable("fp", now, DefaultCheckpointMaxAge); !ok {
		t.Error("fresh matching checkpoint should be usable")
	}
	if ok, why := mk("fp", now.Unix()).Usable("other", now, DefaultCheckpointMaxAge); ok || why == "" {
		t.Error("fingerprint mismatch should be unusable with a reason")
	}
	stale := mk("fp", now.Add(-DefaultCheckpointMaxAge-time.Hour).Unix())
	if ok, why := stale.Usable("fp", now, DefaultCheckpointMaxAge); ok || why == "" {
		t.Error("stale checkpoint should be unusable with a reason")
	}
	future := mk("fp", now.Add(time.Hour).Unix())
	if ok, _ := future.Usable("fp", now, DefaultCheckpointMaxAge); ok {
		t.Error("future-timestamped checkpoint should be unusable")
	}
	// maxAge <= 0 disables the staleness check.
	if ok, _ := stale.Usable("fp", now, 0); !ok {
		t.Error("maxAge=0 should disable staleness check")
	}
}

func TestFrontier_SnapshotRestore(t *testing.T) {
	f := newURLFrontier(10, nil)
	f.Push([]urlEntry{{URL: "https://ex.com/", Depth: 0}})
	entry, _ := f.Pop() // visit the seed
	_ = entry
	f.Push([]urlEntry{
		{URL: "https://ex.com/a", Depth: 1},
		{URL: "https://ex.com/b", Depth: 1},
	})
	f.MarkIdle()

	pending, seen := f.Snapshot()
	if len(pending) != 2 {
		t.Fatalf("pending = %d, want 2 (a,b queued)", len(pending))
	}
	if len(seen) != 3 {
		t.Fatalf("seen = %d, want 3 (seed + a + b)", len(seen))
	}

	// Restore into a fresh frontier: pending resumes, seen keys are skipped.
	f2 := newURLFrontier(10, nil)
	f2.Restore(pending, seen)
	// A previously-seen URL must not re-enqueue.
	if added := f2.Push([]urlEntry{{URL: "https://ex.com/a", Depth: 1}}); added != 0 {
		t.Errorf("restored seen key re-enqueued (added=%d, want 0)", added)
	}
	// The pending queue is resumable.
	if f2.Len() != 2 {
		t.Errorf("restored queue len = %d, want 2", f2.Len())
	}
	// A genuinely new URL still enqueues.
	if added := f2.Push([]urlEntry{{URL: "https://ex.com/c", Depth: 1}}); added != 1 {
		t.Errorf("new URL not enqueued after restore (added=%d, want 1)", added)
	}
}

// TestHTTPPageCap covers the budget fold for the net/http backend, including the
// unlimited-pages sentinel: a request budget must still bind there rather than
// being silently discarded.
func TestHTTPPageCap(t *testing.T) {
	cases := []struct {
		name                  string
		maxPages, maxRequests int
		want                  int
	}{
		{"no request budget leaves pages alone", 100, 0, 100},
		{"requests bind when lower", 100, 3, 3},
		{"pages bind when lower", 5, 50, 5},
		{"equal budgets", 10, 10, 10},
		{"unlimited pages, request budget still binds", 0, 25, 25},
		{"both unlimited", 0, 0, 0},
		{"negative request budget ignored", 100, -1, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpPageCap(tc.maxPages, tc.maxRequests); got != tc.want {
				t.Errorf("httpPageCap(%d, %d) = %d, want %d", tc.maxPages, tc.maxRequests, got, tc.want)
			}
		})
	}
}

// TestLoadCheckpoint_Bounds verifies the decode caps: a checkpoint is host-supplied
// parsed input, so an oversized payload or an over-long slice is rejected rather
// than decoded into memory or silently truncated.
func TestLoadCheckpoint_Bounds(t *testing.T) {
	t.Run("over-long seen slice rejected", func(t *testing.T) {
		cp := &Checkpoint{Version: checkpointVersion, Seen: make([]string, MaxCheckpointEntries+1)}
		var buf bytes.Buffer
		if err := cp.Save(&buf); err != nil {
			t.Fatal(err)
		}
		_, err := LoadCheckpoint(&buf)
		if err == nil || !strings.Contains(err.Error(), "seen entries") {
			t.Errorf("expected seen-entries cap error, got %v", err)
		}
	})

	t.Run("oversized payload rejected", func(t *testing.T) {
		// A valid envelope followed by enough filler to pass the byte cap.
		var buf bytes.Buffer
		buf.WriteString(`{"version":1,"config_fingerprint":"`)
		buf.Write(bytes.Repeat([]byte("a"), MaxCheckpointBytes+64))
		buf.WriteString(`"}`)
		if _, err := LoadCheckpoint(&buf); err == nil {
			t.Error("expected oversized-payload error, got nil")
		}
	})

	t.Run("normal checkpoint still loads", func(t *testing.T) {
		cp := &Checkpoint{Version: checkpointVersion, ConfigFingerprint: "fp", Seen: []string{"a"}}
		var buf bytes.Buffer
		if err := cp.Save(&buf); err != nil {
			t.Fatal(err)
		}
		got, err := LoadCheckpoint(&buf)
		if err != nil {
			t.Fatalf("well-formed checkpoint rejected: %v", err)
		}
		if got.ConfigFingerprint != "fp" {
			t.Errorf("round-trip lost data: %+v", got)
		}
	})
}

// TestCheckpoint_PendingIsExternallyConstructible pins the Phase 4 premise that
// the HOST owns checkpoint storage and hand-back. Checkpoint.Pending previously had
// an unexported element type, so an external consumer could round-trip the artifact
// as opaque JSON but could not build one with pending entries or handle them in a
// typed way. This test is written the way such a consumer would have to write it —
// it does not compile if the element type is unexported.
func TestCheckpoint_PendingIsExternallyConstructible(t *testing.T) {
	cp := &Checkpoint{
		Version:           checkpointVersion,
		ConfigFingerprint: "fp",
		CreatedAtUnix:     time.Now().Unix(),
		Pending: []PendingURL{
			{URL: "https://ex.com/a", Depth: 1},
			{URL: "https://ex.com/b", Depth: 2},
		},
		Seen: []string{"https://ex.com/"},
	}
	var buf bytes.Buffer
	if err := cp.Save(&buf); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadCheckpoint(&buf)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if len(got.Pending) != 2 || got.Pending[1].URL != "https://ex.com/b" || got.Pending[1].Depth != 2 {
		t.Errorf("Pending round-trip = %+v, want the two entries as written", got.Pending)
	}
}

// TestLoadCheckpoint_LegacyPendingWireFormat verifies the on-disk format did not
// change when the pending element type was exported: a checkpoint written before
// that change (untagged struct, so "URL"/"Depth" keys) must still load.
func TestLoadCheckpoint_LegacyPendingWireFormat(t *testing.T) {
	legacy := `{
  "version": 1,
  "config_fingerprint": "abc",
  "created_at_unix": 1700000000,
  "pending": [
    {"URL": "https://ex.com/queued", "Depth": 3}
  ],
  "seen": ["https://ex.com/"]
}`
	got, err := LoadCheckpoint(strings.NewReader(legacy))
	if err != nil {
		t.Fatalf("LoadCheckpoint on a pre-change artifact: %v", err)
	}
	if len(got.Pending) != 1 {
		t.Fatalf("Pending = %+v, want 1 entry", got.Pending)
	}
	if got.Pending[0].URL != "https://ex.com/queued" || got.Pending[0].Depth != 3 {
		t.Errorf("Pending[0] = %+v, want {https://ex.com/queued 3}", got.Pending[0])
	}
}

// TestSnapshot_ExcludesTransientlyFailedPages covers the permanence of a transient
// failure. Checkpoint.Seen is cumulative across every resume cycle, so a page
// dropped after one 503 or DNS blip was blacklisted for the life of the checkpoint.
// A failed page stays in the IN-RUN seen-set (no retry spin within a run) but must
// be absent from the snapshot so the next resumed run tries it again.
func TestSnapshot_ExcludesTransientlyFailedPages(t *testing.T) {
	f := newURLFrontier(3, nil)
	f.Push([]urlEntry{
		{URL: "https://ex.com/ok", Depth: 0},
		{URL: "https://ex.com/broken", Depth: 0},
	})
	f.MarkFailed(urlEntry{URL: "https://ex.com/broken", Depth: 0})

	_, seen := f.Snapshot()
	if slices.Contains(seen, frontierKey("https://ex.com/broken")) {
		t.Errorf("snapshot seen-set contains the failed page, making the drop permanent: %v", seen)
	}
	if !slices.Contains(seen, frontierKey("https://ex.com/ok")) {
		t.Errorf("snapshot seen-set lost a successful page: %v", seen)
	}

	// Still deduped WITHIN this run: a second referrer must not re-enqueue it.
	if n := f.Push([]urlEntry{{URL: "https://ex.com/broken", Depth: 1}}); n != 0 {
		t.Errorf("failed page was re-enqueued in the same run (%d added); it would spend the page budget on retries", n)
	}
}

// TestSnapshot_FailedPageIsCarriedAsPending pins the other half of transient-
// failure handling (Codex review, PR #189). Omitting a failed page from the
// snapshot's seen-set is not enough on its own: the page was POPPED before it
// failed, so it is in neither the queue nor the seen-set, and the checkpoint
// carries it in neither half. It then survives only if some other pending page
// happens to re-link it. It must come back as PENDING.
func TestSnapshot_FailedPageIsCarriedAsPending(t *testing.T) {
	f := newURLFrontier(3, nil)
	f.Push([]urlEntry{{URL: "https://ex.com/broken", Depth: 2}})

	// Pop it, exactly as a worker does before discovering the failure.
	entry, ok := f.Pop()
	if !ok {
		t.Fatal("Pop returned nothing")
	}
	f.MarkFailed(entry)
	f.MarkIdle()

	pending, seen := f.Snapshot()

	if slices.Contains(seen, frontierKey("https://ex.com/broken")) {
		t.Errorf("failed page must not be in the snapshot seen-set: %v", seen)
	}

	var found *PendingURL
	for i := range pending {
		if pending[i].URL == "https://ex.com/broken" {
			found = &pending[i]
		}
	}
	if found == nil {
		t.Fatalf("failed page is in neither Pending nor Seen, so resume drops it entirely: pending=%+v seen=%v", pending, seen)
	}
	if found.Depth != 2 {
		t.Errorf("failed page requeued at Depth %d, want 2 (its original depth)", found.Depth)
	}
}

// TestSnapshot_LastPageFailure_ResumeStillHasWork is the end-to-end shape of the
// same bug: a crawl that covered everything except a final transiently-failed
// page used to checkpoint an empty queue and a complete seen-set, so the resumed
// run had nothing to crawl and the page was never retried.
func TestSnapshot_LastPageFailure_ResumeStillHasWork(t *testing.T) {
	f := newURLFrontier(3, nil)
	f.Push([]urlEntry{{URL: "https://ex.com/only", Depth: 0}})
	entry, _ := f.Pop()
	f.MarkFailed(entry)
	f.MarkIdle()

	pending, seen := f.Snapshot()

	resumed := newURLFrontier(3, nil)
	resumed.Restore(pending, seen)
	if resumed.Len() == 0 {
		t.Fatal("resumed frontier is empty: the failed page was lost, so the resumed run reports nothing to crawl")
	}
}

// TestSnapshot_FailedPendingOrderIsDeterministic pins that requeued failed pages
// do not reintroduce ordering variance. f.failed is a map, so unsorted iteration
// would make the pending order differ run to run for identical input.
func TestSnapshot_FailedPendingOrderIsDeterministic(t *testing.T) {
	build := func() []PendingURL {
		f := newURLFrontier(3, nil)
		urls := []string{"https://ex.com/c", "https://ex.com/a", "https://ex.com/b", "https://ex.com/d"}
		for _, u := range urls {
			f.Push([]urlEntry{{URL: u, Depth: 1}})
		}
		for range urls {
			e, _ := f.Pop()
			f.MarkFailed(e)
			f.MarkIdle()
		}
		pending, _ := f.Snapshot()
		return pending
	}

	want := build()
	for i := range 20 {
		got := build()
		if len(got) != len(want) {
			t.Fatalf("iteration %d: length %d, want %d", i, len(got), len(want))
		}
		for j := range got {
			if got[j].URL != want[j].URL {
				t.Fatalf("iteration %d: pending order differs at %d: %q vs %q", i, j, got[j].URL, want[j].URL)
			}
		}
	}
}

// TestRestore_RevalidatesPendingAgainstScopeAndDepth pins the security fix from
// the Codex review of PR #189. A checkpoint round-trips through host storage and
// its fingerprint is derived from non-secret crawl config, so it cannot be
// authenticated. Restore must therefore re-apply the scope and depth gates that
// Push enforces on every other URL, or a crafted checkpoint seeds the frontier
// with out-of-scope and private-network targets.
func TestRestore_RevalidatesPendingAgainstScopeAndDepth(t *testing.T) {
	inScope := func(u string) bool { return strings.HasPrefix(u, "https://target.test/") }

	f := newURLFrontier(2, inScope)
	f.Restore([]urlEntry{
		{URL: "https://target.test/legit", Depth: 1},
		{URL: "https://evil.test/exfil", Depth: 1},       // out of scope
		{URL: "http://169.254.169.254/latest", Depth: 1}, // link-local, out of scope
		{URL: "https://target.test/too-deep", Depth: 99}, // beyond maxDepth
		{URL: "", Depth: 0},                              // unparseable
	}, nil)

	var got []string
	for {
		e, ok := f.Pop()
		if !ok {
			break
		}
		got = append(got, e.URL)
		f.MarkIdle()
	}

	want := []string{"https://target.test/legit"}
	if !slices.Equal(got, want) {
		t.Errorf("Restore admitted entries it should have rejected.\n got: %v\nwant: %v", got, want)
	}
}

// TestRestore_KeepsLegitimateResumeQueue guards the fix against over-correction:
// re-validating must not reject the normal resumed queue. In particular the
// seen-check Push applies must NOT be applied here, since restored pending
// entries are legitimately already in the checkpoint's seen-set.
func TestRestore_KeepsLegitimateResumeQueue(t *testing.T) {
	inScope := func(u string) bool { return strings.HasPrefix(u, "https://target.test/") }

	f := newURLFrontier(5, inScope)
	pending := []urlEntry{
		{URL: "https://target.test/a", Depth: 1},
		{URL: "https://target.test/b", Depth: 2},
	}
	// The same URLs appear in seen, exactly as a real checkpoint records them.
	seen := []string{frontierKey("https://target.test/a"), frontierKey("https://target.test/b")}

	f.Restore(pending, seen)

	if f.Len() != 2 {
		t.Fatalf("resumed queue has %d entries, want 2; the seen-set must not reject the restored queue", f.Len())
	}
}

// TestRestore_DedupsRepeatedPendingEntries pins that a checkpoint listing the
// same URL more than once queues it once. A corrupted or hand-edited Pending
// list would otherwise spend one page-budget slot per duplicate refetching the
// same page (CodeRabbit review, PR #189).
func TestRestore_DedupsRepeatedPendingEntries(t *testing.T) {
	f := newURLFrontier(5, nil)
	f.Restore([]urlEntry{
		{URL: "https://ex.com/a", Depth: 1},
		{URL: "https://ex.com/a", Depth: 1},
		{URL: "https://ex.com/a?x=1", Depth: 1}, // same frontier key (query stripped)
		{URL: "https://ex.com/b", Depth: 1},
	}, nil)

	if f.Len() != 2 {
		t.Errorf("restored queue has %d entries, want 2 (duplicates must collapse)", f.Len())
	}
}
