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
	"strings"
	"testing"
)

// TEST-001 regression: SetCookies on a BrowserManager whose browser field
// is nil must return a clear "browser not connected" error. The error
// string is load-bearing — crawlHeadless wraps it via `inject cookies: %w`
// and operators may match on it when triaging a failed crawl. The default
// NewBrowserManager path always sets browser, so this guard only fires
// when a caller (test or future refactor) constructs BrowserManager
// directly.
func TestBrowserManager_SetCookies_NilBrowserReturnsError(t *testing.T) {
	bm := &BrowserManager{}
	err := bm.SetCookies(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not connected") {
		t.Errorf("error message %q should contain 'not connected'", err.Error())
	}
}

// Additional guard: calling SetCookies on a nil *BrowserManager must also
// return the same "browser not connected" error rather than panicking
// with a nil-pointer dereference. Matches the CodeRabbit guidance on
// PR #68 review 4156714509.
func TestBrowserManager_SetCookies_NilReceiverReturnsError(t *testing.T) {
	var bm *BrowserManager
	err := bm.SetCookies(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not connected") {
		t.Errorf("error message %q should contain 'not connected'", err.Error())
	}
}
