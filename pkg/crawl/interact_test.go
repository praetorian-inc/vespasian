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

// TestNextInteractionTarget walks the selection the way interactPage does: pick
// one target, mark it used, re-select. The sequence must skip destructive and
// blank labels and never return a label already used (which is also what stops a
// re-queried DOM from yielding the same control twice).
func TestNextInteractionTarget(t *testing.T) {
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
	used := map[string]bool{}
	var got []int
	for {
		idx := nextInteractionTarget(labels, used)
		if idx < 0 {
			break
		}
		got = append(got, idx)
		used[normalizeLabel(labels[idx])] = true
	}
	want := []int{0, 3, 5, 7}
	if !slices.Equal(got, want) {
		t.Errorf("nextInteractionTarget sequence = %v, want %v", got, want)
	}
	// Nothing selectable at all is -1, not a panic or index 0.
	if idx := nextInteractionTarget([]string{"", "Delete"}, nil); idx != -1 {
		t.Errorf("all-unselectable labels returned %d, want -1", idx)
	}
}

// TestClickAllowed pins the pre-click gate as FAIL CLOSED. An unreadable label
// (ok == false) must be a skip: elementLabel returns "" when its reads fail, and
// isDestructiveLabel("") is false, so a gate that consulted only the label would
// permit the click in exactly the mid-re-render case the re-check exists for.
func TestClickAllowed(t *testing.T) {
	cases := []struct {
		label string
		ok    bool
		want  bool
	}{
		{"Load more", true, true},
		{"Delete account", true, false},
		{"", false, false},          // read failed: no evidence either way -> skip
		{"Load more", false, false}, // read failed even with a label present -> skip
		{"", true, false},           // blank label -> skip, matching the up-front scan
	}
	for _, c := range cases {
		if got := clickAllowed(c.label, c.ok); got != c.want {
			t.Errorf("clickAllowed(%q, %v) = %v, want %v", c.label, c.ok, got, c.want)
		}
	}
}

// TestIsDestructiveLabel_IrreversibleCommits covers the labels added because their
// consequences cannot be undone by re-running the crawl. Generic mutating verbs
// (submit, save, search) are deliberately NOT skipped — see the tradeoff note on
// destructiveLabelSubstrings — so they are asserted safe here to pin that choice.
func TestIsDestructiveLabel_IrreversibleCommits(t *testing.T) {
	for _, l := range []string{
		"Pay now", "Submit payment", "Purchase", "Buy now",
		"Place order", "Checkout", "Check out", "Withdraw funds", "Transfer funds",
	} {
		if !isDestructiveLabel(l) {
			t.Errorf("isDestructiveLabel(%q) = false, want true (irreversible commit)", l)
		}
	}
	for _, l := range []string{"Submit", "Save", "Send", "Apply", "Search", "Update", "Create"} {
		if isDestructiveLabel(l) {
			t.Errorf("isDestructiveLabel(%q) = true, want false (generic mutation is in scope for --interact)", l)
		}
	}
}

// TestLeftAssignedPage_FailsClosedOnUnreadableURL pins the fail-closed rule for the
// post-click navigation check. The unreadable case is the whole point: page.Info()
// errors while a document is mid-navigation, which is exactly the state a navigating
// click produces, so "cannot read the URL" must count as "may have navigated".
//
// Before this, the guard read `startURL != "" && now != "" && now != startURL`, so an
// unreadable URL skipped recovery entirely: the pass kept clicking a document the
// worker was never assigned and reported navigated=false, which let visitPage run DOM
// enrichment against a foreign page and push its links and forms into the frontier
// off-budget (LAB-4678 review, QUAL-007/SEC-BE-008).
func TestLeftAssignedPage_FailsClosedOnUnreadableURL(t *testing.T) {
	const assigned = "https://ex.com/dashboard"
	cases := []struct {
		name     string
		now      string
		readable bool
		want     bool
	}{
		{"same URL, readable: stayed put", assigned, true, false},
		{"different URL, readable: navigated", "https://ex.com/other", true, true},
		// The regression cases. Each of these returned false before the fix.
		{"unreadable, empty: must assume navigated", "", false, true},
		{"unreadable but same value: must still assume navigated", assigned, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := leftAssignedPage(c.now, c.readable, assigned); got != c.want {
				t.Errorf("leftAssignedPage(%q, %v, %q) = %v, want %v",
					c.now, c.readable, assigned, got, c.want)
			}
		})
	}
}

// TestMaxInteractionCandidates_ExceedsClickBudget pins the relationship the candidate
// cap depends on. The cap only costs no coverage while it stays well above the click
// budget: reaching it means that many candidates were all rejected, and the pass can
// spend at most maxInteractionsPerPage clicks regardless (SEC-BE-007). Lowering the
// cap toward the click budget would silently start dropping clickable controls.
func TestMaxInteractionCandidates_ExceedsClickBudget(t *testing.T) {
	if maxInteractionCandidates <= maxInteractionsPerPage {
		t.Fatalf("maxInteractionCandidates (%d) must exceed maxInteractionsPerPage (%d), "+
			"or truncating the candidate list can drop clickable controls",
			maxInteractionCandidates, maxInteractionsPerPage)
	}
}
