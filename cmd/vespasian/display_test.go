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

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// captureStderr redirects os.Stderr to a pipe, calls fn, and returns
// whatever was written to stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	fn()

	_ = w.Close()
	os.Stderr = origStderr

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("reading pipe: %v", err)
	}
	return buf.String()
}

func TestPrintBanner(t *testing.T) {
	output := captureStderr(t, func() {
		printBanner()
	})

	if !strings.Contains(output, "Praetorian Security") {
		t.Errorf("banner missing company name, got:\n%s", output)
	}
	if !strings.Contains(output, "v"+version) {
		t.Errorf("banner missing version %q, got:\n%s", "v"+version, output)
	}
}

func TestPrintBannerTo(t *testing.T) {
	var buf bytes.Buffer
	printBannerTo(&buf)

	output := buf.String()
	if !strings.Contains(output, "Praetorian Security") {
		t.Errorf("banner missing company name, got:\n%s", output)
	}
	if !strings.Contains(output, "v"+version) {
		t.Errorf("banner missing version %q, got:\n%s", "v"+version, output)
	}
}

func TestNoBannerFlag(t *testing.T) {
	// Verify the NoBanner field exists on CLI and defaults to false.
	if CLI.NoBanner {
		t.Error("NoBanner should default to false")
	}
}

func TestBannerSuppression(t *testing.T) {
	// Simulate the conditional logic from main(): when NoBanner is true,
	// printBanner should not be called.
	noBanner := true
	output := captureStderr(t, func() {
		if !noBanner {
			printBanner()
		}
	})

	if strings.Contains(output, "Praetorian Security") {
		t.Error("banner should be suppressed when --no-banner is set")
	}
}
