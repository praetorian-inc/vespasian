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

//go:build integration

package crawl

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// processAlive checks if a process with the given PID is running.
// Uses POSIX signal 0 which checks for process existence without
// actually sending a signal.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

// TestBrowserManager_LaunchAndKill verifies that NewBrowserManager launches
// Chrome successfully, returns a valid WS URL, and Kill terminates the process.
func TestBrowserManager_LaunchAndKill(t *testing.T) {
	mgr, err := NewBrowserManager(BrowserOptions{Headless: true})
	if err != nil {
		t.Fatalf("NewBrowserManager() error = %v", err)
	}

	// Verify WS URL looks valid
	wsURL := mgr.WSURL()
	if wsURL == "" {
		t.Fatal("WSURL() returned empty string")
	}
	if !strings.HasPrefix(wsURL, "ws://") {
		t.Errorf("WSURL() = %q, want ws:// prefix", wsURL)
	}

	// Verify Chrome is running
	pid := mgr.PID()
	if pid == 0 {
		t.Fatal("PID() returned 0, expected running Chrome process")
	}

	if !processAlive(pid) {
		t.Errorf("Chrome process %d not running before Kill", pid)
	}

	// Kill and verify Chrome is dead
	mgr.Kill()

	// Give the OS a moment to reap the process
	time.Sleep(500 * time.Millisecond)

	if processAlive(pid) {
		t.Errorf("Chrome process %d still running after Kill", pid)
	}

	// Cleanup temp dir
	mgr.cleanup()
}

// TestBrowserManager_KillIdempotent verifies that calling Kill multiple times
// does not panic or error.
func TestBrowserManager_KillIdempotent(t *testing.T) {
	mgr, err := NewBrowserManager(BrowserOptions{Headless: true})
	if err != nil {
		t.Fatalf("NewBrowserManager() error = %v", err)
	}
	defer mgr.Close()

	// Kill twice — should not panic
	mgr.Kill()
	mgr.Kill()
}

// TestBrowserManager_Close verifies that Close kills Chrome and cleans up
// the temporary user data directory.
func TestBrowserManager_Close(t *testing.T) {
	mgr, err := NewBrowserManager(BrowserOptions{Headless: true})
	if err != nil {
		t.Fatalf("NewBrowserManager() error = %v", err)
	}

	pid := mgr.PID()
	if pid == 0 {
		t.Fatal("PID() returned 0")
	}

	mgr.Close()

	// Give the OS a moment to reap the process
	time.Sleep(500 * time.Millisecond)

	if processAlive(pid) {
		t.Errorf("Chrome process %d still running after Close", pid)
	}
}

// TestBrowserManager_CloseIdempotent verifies that calling Close multiple
// times does not panic.
func TestBrowserManager_CloseIdempotent(t *testing.T) {
	mgr, err := NewBrowserManager(BrowserOptions{Headless: true})
	if err != nil {
		t.Fatalf("NewBrowserManager() error = %v", err)
	}

	mgr.Close()
	// Second close should not panic — both Kill and cleanup are
	// protected by sync.Once.
	mgr.Close()
}
