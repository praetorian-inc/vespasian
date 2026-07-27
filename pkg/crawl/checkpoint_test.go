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
	"strings"
	"testing"
	"time"
)

func TestComputeConfigFingerprint(t *testing.T) {
	base := ComputeConfigFingerprint("https://ex.com", "same-origin", 3, true)
	if base == "" {
		t.Fatal("empty fingerprint")
	}
	if base != ComputeConfigFingerprint("https://ex.com", "same-origin", 3, true) {
		t.Error("fingerprint not stable for identical inputs")
	}
	// Each defining field changes the fingerprint, including the backend: the
	// two backends discover different link sets, so a headless checkpoint must
	// not be reusable by the net/http backend.
	for _, fp := range []string{
		ComputeConfigFingerprint("https://other.com", "same-origin", 3, true),
		ComputeConfigFingerprint("https://ex.com", "same-domain", 3, true),
		ComputeConfigFingerprint("https://ex.com", "same-origin", 5, true),
		ComputeConfigFingerprint("https://ex.com", "same-origin", 3, false),
	} {
		if fp == base {
			t.Error("fingerprint did not change when a defining field changed")
		}
	}
	// Length-prefixing prevents field-boundary collisions.
	if ComputeConfigFingerprint("ab", "", 0, true) == ComputeConfigFingerprint("a", "b", 0, true) {
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
