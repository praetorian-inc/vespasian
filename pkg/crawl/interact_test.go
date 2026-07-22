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
	"slices"
	"testing"
)

func TestIsDestructiveLabel(t *testing.T) {
	destructive := []string{
		"Delete", "Delete account", "Remove item", "Log out", "Logout",
		"Sign out", "Deactivate", "Reset password", "Revoke token",
		"CLEAR ALL", "  wipe data  ", "Unsubscribe",
	}
	for _, l := range destructive {
		if !isDestructiveLabel(l) {
			t.Errorf("isDestructiveLabel(%q) = false, want true", l)
		}
	}
	safe := []string{
		"Submit", "Load more", "Next", "View details", "Search",
		"Add to cart", "Refresh list", "", "Open menu", "Filter",
	}
	for _, l := range safe {
		if isDestructiveLabel(l) {
			t.Errorf("isDestructiveLabel(%q) = true, want false", l)
		}
	}
}

func TestSelectInteractionTargets(t *testing.T) {
	labels := []string{
		"Load more", // 0 keep
		"Delete",    // 1 skip (destructive)
		"",          // 2 skip (blank)
		"View",      // 3 keep
		"load more", // 4 skip (dup of 0, case-insensitive)
		"Next page", // 5 keep
		"Sign out",  // 6 skip (destructive)
		"Details",   // 7 keep
	}
	got := selectInteractionTargets(labels, maxInteractionsPerPage)
	want := []int{0, 3, 5, 7}
	if !slices.Equal(got, want) {
		t.Errorf("selectInteractionTargets = %v, want %v", got, want)
	}
}

func TestSelectInteractionTargets_Cap(t *testing.T) {
	labels := []string{"a", "b", "c", "d", "e"}
	got := selectInteractionTargets(labels, 3)
	if len(got) != 3 {
		t.Errorf("len = %d, want 3 (capped)", len(got))
	}
	if !slices.Equal(got, []int{0, 1, 2}) {
		t.Errorf("got %v, want first 3 indices", got)
	}
	// A non-positive cap selects nothing.
	if n := selectInteractionTargets(labels, 0); n != nil {
		t.Errorf("max=0 selected %v, want nil", n)
	}
}
