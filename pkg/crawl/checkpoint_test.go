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
	"testing"
	"time"
)

func TestComputeConfigFingerprint(t *testing.T) {
	base := ComputeConfigFingerprint("https://ex.com", "same-origin", 3)
	if base == "" {
		t.Fatal("empty fingerprint")
	}
	if base != ComputeConfigFingerprint("https://ex.com", "same-origin", 3) {
		t.Error("fingerprint not stable for identical inputs")
	}
	// Each defining field changes the fingerprint.
	for _, fp := range []string{
		ComputeConfigFingerprint("https://other.com", "same-origin", 3),
		ComputeConfigFingerprint("https://ex.com", "same-domain", 3),
		ComputeConfigFingerprint("https://ex.com", "same-origin", 5),
	} {
		if fp == base {
			t.Error("fingerprint did not change when a defining field changed")
		}
	}
	// Length-prefixing prevents field-boundary collisions.
	if ComputeConfigFingerprint("ab", "", 0) == ComputeConfigFingerprint("a", "b", 0) {
		t.Error("field-boundary collision")
	}
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
